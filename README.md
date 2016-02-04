PKI Util
=============
This is a simple util with which users can create a private key and CSR for sending to an Certificate Authority for signing.

PKI Util creates private RSA keys with 4096 bits and then creates a Certificate Signing Request with the given input using the sha256withRSAEncryption signature algorithm.

The created key and CSR are written to a file and have the password "changeit" - which is the default for Java Key Stores.

Once the CSR has been signed by a CA, the PKI Util can be used once again to create a PKCS12 and JKS export. The prior can be used in a web browser as a client certificate, and the latter as a KeyStore in Java based applications.

The use case for this util is to simplify the creation of a CSR when a Client Certificate is to be created. In other cases this utility might not be as practical, but can alsow fulfil the needs.

Bugs, issues, features can be requested on GitHub: https://github.com/eitch/ch.eitchnet.pki/issues

Written and created by Robert von Burg <eitch@eitchnet.ch>

Usage
=============
The PKI Util can either be started directly using Java:
<pre>
java -jar PkiUtil.jar (csr | export)
</pre>
or by using the scripts.

Unix based systems:
<pre>
./csr.sh
./export.sh
</pre>

Windows:
<pre>
./csr.sh
./export.sh
</pre> 

The PKI Util has two functions, one is to create a certificate signing request, and the other is to export a signed certificate in the form PKCS12 and JKS.

Certificate signing request
-------------------------
Example session to create a CSR:
<pre>
$ ./csr.sh
Certificate Signing Request
===========================

Please enter the following fields as input
for the subject of the certificate signing request
The values in brackets are default values:

Country [CH] : CH
State/Province [Zürich] : Solothurn
City [Zürich] : Solothurn
Organisation [My Company] : Awesome GmbH
Organisational Unit [Development] : Development
Common Name [www.mycompany.ch] : www.awesome-gmbh.ch
E-Mail [dev@mycompany.ch] : dev@awesome-gmbh.ch

Do you want to use the following subject:
C=CH,ST=Solothurn,L=Solothurn,O=Awesome GmbH,OU=Development,CN=www.awesome-gmbh.ch,1.2.840.113549.1.9.1=#161364657640617765736f6d652d676d62682e6368

y/n [y] : y
Initializing KeyPair...
Creating Certificate Signing Request...
Writing PrivateKey to www.awesome-gmbh.ch.key
Writing CSR to www.awesome-gmbh.ch.csr
</pre>

**Note 1:** The resulting key is not password protected and must be kept safe at all times!

**Note 2:** The .csr file should be sent to the CA of your choice.

Export
------------------
Once the CA of your choice has signed and returned the Certificate to you, it can be exported.

Example session to create the exported certificates:
<pre>
$ ./export.sh
Export
===========================

Private key file name [] : www.awesome-gmbh.ch.key
Read private and public key www.awesome-gmbh.ch.key using RSA in format PKCS#8
Certificate file name [] : www.awesome-gmbh.ch.crt
Read certificate www.awesome-gmbh.ch.crt
Certificate is signed by CN=The CA,OU=Dev,O=Internet Widgits Pty Ltd,L=Solothurn,ST=Solothurn,C=CH
Certificate has subject C=CH,ST=Solothurn,L=Solothurn,O=Awesome GmbH,OU=Development,CN=www.awesome-gmbh.ch,1.2.840.113549.1.9.1=#161364657640617765736f6d652d676d62682e6368

Do you want to use this certificate?

y/n [y] : y
Parsing Subject from Certificate...
Writing PKCS12 to www.awesome-gmbh.ch.p12
Keystore password: changeit
Writing JKS to www.awesome-gmbh.ch.jks
Keystore password: changeit
</pre>

The result of the session is a PKCS12 certificate, which can be used in a browser and other applications. The JKS file can be used in a Java application and contains the private key and signed certificate with which you can authenticate yourself to a server.

**Note:** The resulting files both have a default passwort of `changeit`.

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

Checks and debugging:
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