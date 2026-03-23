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

This should be needed only very rarely and need not be automated.

Copy the root cert also to Gideon.

The root key remains in this directory and will only be accessible to the root user.

Generate the active cert
------------------------

Run the gen-cert script.
