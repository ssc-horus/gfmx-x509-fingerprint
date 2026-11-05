// Command gfmx prints the GFMX fingerprint of X.509 certificates.
//
//	gfmx [flags] [FILE|DIR|-]...
//
// Inputs: PEM files (any number of certificates), DER files, folders (their .pem,
// .crt, .cer and .der files), '-' for stdin (PEM, DER, or one hex/base64 certificate
// per line), --host for a live TLS server. Output keeps input order at any --workers.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ssc-horus/gfmx-x509-fingerprint/go/extract"
	"github.com/ssc-horus/gfmx-x509-fingerprint/go/gfmx"
)

type item struct {
	source string
	der    []byte
	err    error // input-level error (unreadable file, bad encoding)
}

type row struct {
	Source string    `json:"source"`
	SHA256 string    `json:"sha256"`
	GFMX   *string   `json:"gfmx"`
	Raw    *gfmx.Raw `json:"raw"`
	Info   *string   `json:"info"`
	Error  *string   `json:"error"`
}

var pemRE = regexp.MustCompile(`(?s)-----BEGIN ((?:X509 |TRUSTED )?)CERTIFICATE-----(.+?)-----END (?:X509 |TRUSTED )?CERTIFICATE-----`)
var hexRE = regexp.MustCompile(`^(?:[0-9A-Fa-f]{2}[:\s]?)+$`)

func b64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '\v' || r == '\f' {
			return -1
		}
		return r
	}, s)
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// loadBytes splits an input into certificates: PEM blocks, one raw DER, or text lines
// holding one hex or base64 certificate each.
func loadBytes(data []byte) ([][]byte, error) {
	if m := pemRE.FindAllSubmatch(data, -1); len(m) > 0 {
		out := make([][]byte, 0, len(m))
		for _, x := range m {
			der, err := b64(string(x[2]))
			if err != nil {
				return nil, fmt.Errorf("bad PEM block: %v", err)
			}
			if string(x[1]) == "TRUSTED " { // X509_AUX: certificate, then trust settings
				der = extract.FirstElement(der)
			}
			out = append(out, der)
		}
		return out, nil
	}
	if len(data) > 0 && data[0] == 0x30 {
		return [][]byte{data}, nil
	}
	for _, c := range data {
		if c >= 0x80 {
			return [][]byte{data}, nil
		}
	}
	var out [][]byte
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line := strings.Trim(sc.Text(), " \t\r\n\v\f")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "30") && hexRE.MatchString(line) {
			der, err := hex.DecodeString(strings.Map(func(r rune) rune {
				if r == ':' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f' {
					return -1
				}
				return r
			}, line))
			if err != nil {
				return [][]byte{data}, nil
			}
			out = append(out, der)
			continue
		}
		der, err := b64(line)
		if err != nil { // not a list of certificates: let the DER parser report it
			return [][]byte{data}, nil
		}
		out = append(out, der)
	}
	return out, nil
}

// expand lists the inputs; a folder that cannot be read is returned in errs and the
// run reports it (exit status 2) and carries on.
func expand(paths []string) (out []string, errs map[string]error) {
	errs = map[string]error{}
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			ents, err := os.ReadDir(p)
			if err != nil {
				errs[p] = err
				out = append(out, p)
				continue
			}
			var names []string
			for _, e := range ents {
				n := strings.ToLower(e.Name())
				if !e.IsDir() && certExt[strings.ToLower(filepath.Ext(n))] {
					names = append(names, filepath.Join(p, e.Name()))
				}
			}
			sort.Strings(names)
			out = append(out, names...)
		} else {
			out = append(out, p)
		}
	}
	return out, errs
}

// certExt: file types a folder expands to (explicitly named files are always read).
var certExt = map[string]bool{
	".pem": true, ".der": true, ".crt": true, ".cer": true, // certificates
	".p7b": true, ".p7c": true, ".p7s": true, ".spc": true, ".cat": true, // PKCS#7 / CMS
	".apk": true, ".apks": true, ".xapk": true, ".jar": true, // signed ZIPs
	".exe": true, ".dll": true, ".sys": true, ".efi": true, ".ocx": true, ".scr": true, // Authenticode
}

func splitHostPort(hp string) (string, string) {
	if h, p, err := net.SplitHostPort(hp); err == nil {
		return h, p
	}
	return strings.Trim(hp, "[]"), "443"
}

// legacySuites lists every TLS 1.0-1.2 cipher suite Go implements, including those it
// no longer offers by default (RSA key exchange since Go 1.22, 3DES since Go 1.23).
// --host fingerprints whatever a server presents, and old appliances often offer
// nothing newer. Nothing is validated, so a weak suite costs nothing here.
// (SHA-1 handshake signatures, refused by default from Go 1.25, stay accepted because
// go.mod's go line keeps the Go 1.24 defaults.)
func legacySuites() []uint16 {
	var ids []uint16
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		for _, v := range s.SupportedVersions {
			if v != tls.VersionTLS13 {
				ids = append(ids, s.ID)
				break
			}
		}
	}
	return ids
}

// fetchLeaf returns the certificate a server presents in a TLS handshake. Validation
// is off on purpose. The SNI sent is sni when given, else the host when it is a name;
// an IP address without sni sends none, and the server answers with its default
// certificate.
func fetchLeaf(hp, sni string, timeout time.Duration) ([]byte, error) {
	host, port := splitHostPort(hp)
	d := &net.Dialer{Timeout: timeout}
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, CipherSuites: legacySuites()}
	switch {
	case sni != "":
		cfg.ServerName = sni
	case net.ParseIP(host) == nil:
		cfg.ServerName = host
	}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, port), cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s presented no certificate", hp)
	}
	return certs[0].Raw, nil
}

var carve bool

// certsOf returns the certificates in one input: containers (APK/JAR, PE, PKCS#7, PEM
// with PKCS7 blocks) are opened by package extract; anything else is read as PEM, DER,
// or hex/base64 lines, exactly as the reference implementation does.
func certsOf(data []byte) ([]extract.Cert, error) {
	k := extract.Kind(data)
	p7pem := bytes.Contains(data, []byte("-----BEGIN PKCS7-----")) || bytes.Contains(data, []byte("-----BEGIN CMS-----"))
	if carve || k == "zip" || k == "pe" || k == "pkcs7" || p7pem {
		if cs, ok := extract.Certificates(data, extract.Options{Carve: carve}); ok {
			return cs, nil
		}
	}
	ders, err := loadBytes(data)
	if err != nil {
		return nil, err
	}
	out := make([]extract.Cert, len(ders))
	for i, d := range ders {
		out[i] = extract.Cert{DER: d}
	}
	return out, nil
}

func produce(files, hosts, b64s []string, sni string, out chan<- item) {
	defer close(out)
	paths, dirErrs := expand(files)
	for _, p := range paths {
		if err, bad := dirErrs[p]; bad {
			out <- item{source: p, err: err}
			continue
		}
		var data []byte
		var err error
		label := p
		if p == "-" {
			data, err = io.ReadAll(os.Stdin)
			label = "stdin"
		} else {
			data, err = os.ReadFile(p)
		}
		if err != nil {
			out <- item{source: label, err: err}
			continue
		}
		certs, err := certsOf(data)
		if err != nil {
			out <- item{source: label, err: err}
			continue
		}
		for n, c := range certs {
			src := label
			switch {
			case c.Source != "":
				src = label + "!" + c.Source
			case n > 0 || label == "stdin":
				src = fmt.Sprintf("%s#%d", label, n)
			}
			out <- item{source: src, der: c.DER}
		}
	}
	for _, hp := range hosts {
		der, err := fetchLeaf(hp, sni, 10*time.Second)
		out <- item{source: hp, der: der, err: err}
	}
	for n, s := range b64s {
		der, err := b64(s)
		out <- item{source: fmt.Sprintf("b64#%d", n), der: der, err: err}
	}
}

func process(it item) (row, bool) {
	r := row{Source: it.source}
	if it.err != nil {
		e := it.err.Error()
		r.Error = &e
		return r, false
	}
	sum := sha256.Sum256(it.der)
	r.SHA256 = hex.EncodeToString(sum[:])
	res, err := gfmx.Fingerprint(it.der)
	if err != nil {
		e := err.Error()
		r.Error = &e
		return r, true
	}
	r.GFMX, r.Raw, r.Info = &res.GFMX, &res.Raw, &res.Info
	return r, true
}

func main() {
	var hosts, b64s multi
	jsonOut := flag.Bool("json", false, "one JSON object per certificate")
	raw := flag.Bool("raw", false, "print each segment's pre-hash string")
	csvPath := flag.String("csv", "", "also write a table to this CSV file")
	quiet := flag.Bool("quiet", false, "no per-certificate output")
	workers := flag.Int("workers", runtime.NumCPU(), "parallel workers")
	version := flag.Bool("version", false, "print version and exit")
	flag.BoolVar(&carve, "carve", false, "also find certificates embedded anywhere in the input (binaries, firmware, memory dumps)")
	flag.Var(&hosts, "host", "fingerprint the certificate a live TLS server presents (HOST[:PORT], repeatable)")
	sni := flag.String("sni", "", "server name to send with --host (default: the host when it is a name; none for an IP)")
	flag.Var(&b64s, "b64", "base64 DER certificate (repeatable)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: gfmx [flags] [FILE|DIR|-]...\n\n"+
			"GFMX: X.509 certificate template fingerprint (KEY:SPAN:MAKER:AUDIENCE:NAMES).\n\n"+
			"Inputs: PEM, DER, PKCS#7/CMS (.p7b .p7s .cat), signed APK/JAR (v1-v3.1, lineage,\n"+
			"source stamp, split bundles), Authenticode PE (.exe .dll .sys), folders, and '-'\n"+
			"for stdin (any of these, or one hex/base64 certificate per line).\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExit status: 0 all certificates fingerprinted, 1 at least one could not be parsed, 2 usage or input error.\n")
	}
	args := parseInterleaved()
	if *version {
		fmt.Printf("gfmx %s (spec %s)\n", gfmx.Version, gfmx.SpecVersion)
		return
	}
	if len(args) == 0 && len(hosts) == 0 && len(b64s) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if *workers < 1 {
		*workers = 1
	}

	// ordered parallel pipeline: each item carries a result slot
	type job struct {
		it   item
		done chan struct{}
		r    row
		cert bool
	}
	items := make(chan item, 1024)
	go produce(args, hosts, b64s, *sni, items)
	jobs := make(chan *job, 4096)
	ordered := make(chan *job, 4096)
	go func() {
		for it := range items {
			j := &job{it: it, done: make(chan struct{})}
			ordered <- j
			jobs <- j
		}
		close(jobs)
		close(ordered)
	}()
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				j.r, j.cert = process(j.it)
				close(j.done)
			}
		}()
	}

	stdout := bufio.NewWriterSize(os.Stdout, 1<<16)
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	var cw *csv.Writer
	var cf *os.File
	if *csvPath != "" {
		var err error
		if cf, err = os.Create(*csvPath); err != nil {
			fmt.Fprintln(os.Stderr, "gfmx:", err)
			os.Exit(2)
		}
		cw = csv.NewWriter(cf)
		cw.Write([]string{"file", "gfmx", "raw_key", "raw_span", "raw_maker", "raw_audience",
			"raw_names", "info", "sha256", "error"})
	}
	n, failed, inputErr := 0, 0, 0
	for j := range ordered {
		<-j.done
		r := j.r
		if !j.cert {
			inputErr++
			fmt.Fprintf(os.Stderr, "gfmx: %s: %s\n", r.Source, *r.Error)
			continue
		}
		n++
		if r.Error != nil {
			failed++
		}
		if cw != nil {
			x, rk := "!:!:!:!:!", gfmx.Raw{}
			info, e := "", ""
			if r.GFMX != nil {
				x, rk, info = *r.GFMX, *r.Raw, *r.Info
			}
			if r.Error != nil {
				e = *r.Error
			}
			cw.Write([]string{filepath.Base(r.Source), x, rk.Key, rk.Span, rk.Maker, rk.Audience,
				rk.Names, info, r.SHA256, e})
		}
		if *quiet {
			continue
		}
		switch {
		case *jsonOut:
			enc.Encode(r)
		case r.Error != nil:
			fmt.Fprintf(stdout, "%-44s %s  (%s)\n", "error", r.Source, *r.Error)
		default:
			fmt.Fprintf(stdout, "%-44s %s\n", *r.GFMX, r.Source)
			if *raw {
				for _, kv := range [][2]string{{"key", r.Raw.Key}, {"span", r.Raw.Span},
					{"maker", r.Raw.Maker}, {"audience", r.Raw.Audience}, {"names", r.Raw.Names}} {
					fmt.Fprintf(stdout, "    %-8s %s\n", kv[0], kv[1])
				}
				fmt.Fprintf(stdout, "    %-8s %s  (not hashed)\n", "info", *r.Info)
			}
		}
	}
	wg.Wait()
	stdout.Flush()
	if cw != nil {
		cw.Flush()
		werr := cw.Error()
		if cerr := cf.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			fmt.Fprintf(os.Stderr, "gfmx: cannot write %s: %v\n", *csvPath, werr)
			os.Exit(2)
		}
		msg := fmt.Sprintf("%d certificates fingerprinted -> %s", n, *csvPath)
		if failed > 0 {
			msg += fmt.Sprintf(" (%d could not be parsed)", failed)
		}
		fmt.Fprintln(os.Stderr, msg)
	}
	switch {
	case inputErr > 0:
		os.Exit(2)
	case failed > 0:
		os.Exit(1)
	}
}

// parseInterleaved accepts flags before and after the inputs (gfmx certs/ --json),
// like the reference CLI. "--" ends flag parsing; "-" is stdin.
func parseInterleaved() []string {
	var args []string
	rest := os.Args[1:]
	for {
		flag.CommandLine.Parse(rest)
		rest = flag.Args()
		for len(rest) > 0 && (rest[0] == "-" || !strings.HasPrefix(rest[0], "-")) {
			args = append(args, rest[0])
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return args
		}
		if rest[0] == "--" {
			return append(args, rest[1:]...)
		}
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }
