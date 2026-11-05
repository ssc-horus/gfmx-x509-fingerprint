// Package main builds libgfmx, a C ABI for embedding GFMX in C, C++, Rust or
// anything with an FFI (Zeek plugins, YARA modules, sandboxes):
//
//	go build -buildmode=c-shared  -o libgfmx.so ./capi   (also writes libgfmx.h)
//	go build -buildmode=c-archive -o libgfmx.a  ./capi
//
// All functions are thread-safe. Strings returned by gfmx_json are freed with
// gfmx_free.
package main

/*
#include <stddef.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"unsafe"

	"github.com/ssc-horus/gfmx-x509-fingerprint/go/gfmx"
)

// gfmx_fingerprint writes the NUL-terminated fingerprint of one DER certificate to
// out (outlen >= 45). Returns 0 on success, -1 if the certificate cannot be parsed,
// -2 if out is too small.
//
//export gfmx_fingerprint
func gfmx_fingerprint(der *C.uchar, derlen C.size_t, out *C.char, outlen C.size_t) C.int {
	r, err := gfmx.Fingerprint(C.GoBytes(unsafe.Pointer(der), C.int(derlen)))
	if err != nil {
		return -1
	}
	if int(outlen) < len(r.GFMX)+1 {
		return -2
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(outlen))
	copy(dst, r.GFMX)
	dst[len(r.GFMX)] = 0
	return 0
}

// gfmx_json returns {"gfmx":...,"raw":{...},"info":...} or {"error":...} as a
// malloc'd NUL-terminated string; free it with gfmx_free.
//
//export gfmx_json
func gfmx_json(der *C.uchar, derlen C.size_t) *C.char {
	r, err := gfmx.Fingerprint(C.GoBytes(unsafe.Pointer(der), C.int(derlen)))
	var b []byte
	if err != nil {
		b, _ = json.Marshal(map[string]string{"error": err.Error()})
	} else {
		b, _ = json.Marshal(r)
	}
	return C.CString(string(b))
}

//export gfmx_free
func gfmx_free(p *C.char) { C.free(unsafe.Pointer(p)) }

var version = C.CString(gfmx.Version + " (spec " + gfmx.SpecVersion + ")")

//export gfmx_version
func gfmx_version() *C.char { return version }

func main() {}
