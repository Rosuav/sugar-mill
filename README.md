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

Next steps
----------

* Make gen-cert check the certificate validity and do nothing if still
  plenty of time (but maybe allow a "force" parameter)
* Schedule gen-cert using cron
