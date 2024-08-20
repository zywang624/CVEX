Generate a new root certificate:

```
openssl req -x509 -sha256 -days 10365 -newkey rsa:2048 -keyout rootCA.key -out rootCA.crt -nodes
```

Generate a certificate based on the root certificate:

```
openssl req -newkey rsa:2048 -nodes -keyout linux.key -out linux.csr
openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in linux.csr -out linux.crt -days 10365 -CAcreateserial -extfile default.cfg
```

Generate an empty CRL:
```
openssl ca -config default.cfg -gencrl -keyfile rootCA.key -cert rootCA.crt -out root.crl.pem
openssl crl -inform PEM -in root.crl.pem -outform DER -out root.crl
```

