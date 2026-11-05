##! Log every X.509 certificate Zeek sees as base64 DER, so it can be fingerprinted
##! with GFMX (zeek_gfmx.py adds the fingerprint column).
##!
##!   zeek -r capture.pcap gfmx.zeek          # writes gfmx_der.log
##!   zeek_gfmx.py gfmx_der.log > gfmx.log
##!
##! Zeek's own x509.log keeps parsed fields only; GFMX needs the certificate's DER
##! bytes. Certificates are visible in TLS 1.2 and earlier (TLS 1.3 encrypts them).
##! The log carries Zeek's own keys (fuid, uid) and nothing about which side sent the
##! certificate: join on fuid with x509.log / files.log, or on uid with ssl.log and
##! conn.log, for the roles Zeek itself assigns.

@load base/files/x509

module GFMX;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:     time   &log;
		fuid:   string &log;
		uid:    string &log &optional;   ## first connection that carried the certificate
		der:    string &log;             ## base64 DER
	};
}

event zeek_init()
	{
	Log::create_stream(GFMX::LOG, [$columns=Info, $path="gfmx_der"]);
	}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
	{
	local rec = Info($ts=network_time(), $fuid=f$id,
	                 $der=encode_base64(x509_get_certificate_string(cert_ref)));
	if ( f?$conns )
		for ( cid, c in f$conns )
			{
			rec$uid = c$uid;
			break;
			}
	Log::write(GFMX::LOG, rec);
	}
