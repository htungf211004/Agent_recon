# Local TLS fixture

`recon-test-cert.pem` and `recon-test-key.pem` are a self-signed certificate and a
publicly committed **test-only** private key for `recon.test`. They are never used
by the production runtime. The tests explicitly trust this certificate only in
their injected HTTP transport; production certificate verification remains enabled.

Regenerate with OpenSSL if the certificate expires:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout recon-test-key.pem -out recon-test-cert.pem -days 3650 -subj /CN=recon.test -addext subjectAltName=DNS:recon.test
```
