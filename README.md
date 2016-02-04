PKI Util
=============
This is a simple util with which users can create a private key and CSR for sending to an Certificate Authority for signing.

PKI Util creates private RSA keys with 4096 bits and then creates a Certificate Signing Request with the given input using the sha256withRSAEncryption signature algorithm.

The created key and CSR are written to a file and have the password "changeit" - which is the default for Java Key Stores.

Once the CSR has been signed by a CA, the PKI Util can be used once again to create a PKCS12 and JKS export. The prior can be used in a web browser as a client certificate, and the latter as a KeyStore in Java based applications.

OpenSSL commands to perform the same and verify the resulting files
=============

Create an example CA Key and cert:
---------------
openssl genrsa -des3 -out ca.key 4096
openssl req -new -sha256 -x509 -days 365 -key ca.key -out ca.crt

Create Client Key and CSR:
---------------
openssl genrsa -des3 -out client.key 4096
openssl req -new -sha256 -key client.key -out client.csr

Sign a client CSR with a CA:
---------------
openssl x509 -req -sha256 -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 101 -extensions client -outform PEM -out client.crt

Create the PKCS12 Cert:
---------------
openssl pkcs12 -export -inkey client.key -in client.crt -out client.p12

Create PEM Key and Cert from PKCS12
---------------
openssl pkcs12 -nocerts -in client.p12 -out client.key
openssl pkcs12 -clcerts  -nokeys -in client.p12 -out client.crt

Create TrustStore for CA
---------------
keytool -import -file ca.crt -alias CA -keystore CA_TrustStore.jks

Create KeyStore for client certificate:
---------------
keytool -importkeystore -destkeystore KeyStore.jks -srckeystore client.p12 -srcstoretype PKCS12

Checks:
===============
Check a Certificate Signing Request (CSR)
---------------
openssl req -text -noout -verify -in client.csr

Check a private key
---------------
openssl rsa -in client.key -check -noout

Check a certificate
---------------
openssl x509 -in client.crt -text -noout

Check a PKCS#12 file (.pfx or .p12)
---------------
openssl pkcs12 -info -in client.p12 -noout