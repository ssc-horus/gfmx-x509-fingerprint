#!/usr/bin/env bash
# Make self-signed and issued certificates for every key type and digest the
# self-signature check supports (plus two it must report as "u": explicit curve
# parameters and prime239v1). Used to build testdata/vectors.jsonl.
# Usage: gen_alg_certs.sh OUT_DIR    (needs the openssl CLI, 3.0+)
set -e
mkdir -p "${1:?usage: gen_alg_certs.sh OUT_DIR}"
cd "$1"
k(){ openssl genpkey "$@" 2>/dev/null; }
k -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key
k -algorithm RSA -pkeyopt rsa_keygen_bits:2049 -out rsa2049.key
k -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out rsapss.key
openssl dsaparam -genkey -out dsa1k.key 1024 2>/dev/null
openssl dsaparam -genkey -out dsa2k.key 2048 2>/dev/null
for c in prime192v1 P-224 P-256 P-384 P-521 secp256k1 brainpoolP256r1 brainpoolP384r1 brainpoolP512r1 prime239v1; do k -algorithm EC -pkeyopt ec_paramgen_curve:$c -out ec_$c.key; done
k -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt point-format:compressed -out ec_P-256c.key
k -algorithm EC -pkeyopt ec_paramgen_curve:P-224 -pkeyopt point-format:compressed -out ec_P-224c.key
k -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:explicit -out ec_P-256x.key
k -algorithm ed25519 -out ed25519.key; k -algorithm ed448 -out ed448.key
mk(){ openssl req -x509 -new -subj "$3" -days $4 -outform DER -key $1.key -out c_$2.der "${@:5}" 2>/dev/null || echo "skip $2"; }
i=0
for key in rsa rsa2049 rsapss dsa1k dsa2k ed25519 ed448 ec_prime192v1 ec_P-224 ec_P-256 ec_P-384 ec_P-521 ec_secp256k1 ec_brainpoolP256r1 ec_brainpoolP384r1 ec_brainpoolP512r1 ec_prime239v1 ec_P-256c ec_P-224c ec_P-256x; do
  for md in "" -md5 -sha1 -sha224 -sha256 -sha384 -sha512 -sha3-256 -sha512-256; do
    i=$((i+1)); mk $key ${key}${md} "/CN=t$i/O=Org $i/C=US" $((i*37)) $md
  done
done
for md in -sha256 -sha1 -sha512; do mk rsa pss$md "/CN=pss" 90 $md -sigopt rsa_padding_mode:pss; mk rsa2049 pss2049$md "/CN=pss" 90 $md -sigopt rsa_padding_mode:pss; done
mk rsa pss0 "/CN=pss" 90 -sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:0
# issued (not self-signed), with extensions
openssl req -x509 -new -subj "/CN=ca" -days 3650 -key rsa.key -out ca.pem 2>/dev/null
for key in ec_P-256 ed25519 rsapss; do
 openssl req -new -subj "/CN=leaf/OU=x+serialNumber=12" -key $key.key -out l.csr 2>/dev/null
 printf "subjectAltName=DNS:a.example,URI:spiffe://x\nextendedKeyUsage=serverAuth,clientAuth,codeSigning\nkeyUsage=critical,digitalSignature\nauthorityInfoAccess=OCSP;URI:http://o.example,caIssuers;URI:ldap://l.example\ncrlDistributionPoints=URI:http://c.example/x.crl\ncertificatePolicies=2.23.140.1.2.1,1.2.3.4\nbasicConstraints=critical,CA:true,pathlen:3\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n" > ext.cnf
 openssl x509 -req -in l.csr -CA ca.pem -CAkey rsa.key -set_serial 0x$(openssl rand -hex 20) -days 397 -extfile ext.cnf -outform DER -out c_issued_$key.der 2>/dev/null
done
ls c_*.der | wc -l
