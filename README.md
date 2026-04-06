Automating my own Certificate Signing Requests
==============================================

To get client certs, I need my own CSA. This shall be called the Sugar Mill
in memory of the witches.

Generate the signing authority self-signed cert
-----------------------------------------------

    # openssl genrsa -des3 -passout pass: -out sugarmill.rosuav.com.key 4096
    # openssl req -x509 -new -nodes -passin pass: -key sugarmill.rosuav.com.key -sha256 -days 3650 -out sugarmill.rosuav.com.pem -subj '/CN=sugarmill.rosuav.com'
    # cp sugarmill.rosuav.com.pem /usr/local/share/ca-certificates/
    # update-ca-certificates
    # scp sugarmill.rosuav.com.pem gideon:/usr/local/share/ca-certificates/
    # ssh gideon update-ca-certificates

This should be needed only very rarely and need not be automated.

Gideon needs the cert, but not the key.

Generating the active cert is done by the gen-cert script.

Providing certificates and keys to clients
------------------------------------------

A separate server, keyfob.py, provides the certs and keys on demand. It is
accessed using a Unix socket, and will verify (to the extent it can) that the
caller is a valid recipient.

- TODO: Check the process owner and make sure it's right
- TODO: Check something else?
- TODO: Generate an actual secret instead of using Hello World example

Establish a socket connection, then use line-based commands with args:

* S: hello
* C: auth 12345678
* S: login ok/bad
* C: req db.rosuav.com
* S: key\n.........\n.\n
* S: cert\n.........\n.\n

Client MAY retain the connection after this and MAY request other key/cert pairs.

- TODO: Server provide new keys when they rotate?
