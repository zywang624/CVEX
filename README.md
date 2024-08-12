Generate a new root certificate:
openssl req -x509 -sha256 -days 10365 -newkey rsa:2048 -keyout rootCA.key -out rootCA.crt -nodes

Generate a certificate based on the root certificate:
openssl req -newkey rsa:2048 -nodes -keyout linux.key -out linux.csr
openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in linux.csr -out linux.crt -days 10365 -CAcreateserial -extfile linux.ext


linux.ext file:
```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName = @alt_names
[alt_names]
DNS.1 = linux
```
