Automating my own Certificate Signing Requests
==============================================

To get client certs, I need my own CSA. This shall be called the Sugar Mill
in memory of the witches.

Generate the signing authority self-signed cert
-----------------------------------------------

$ openssl genrsa -des3 -passout pass: -out sugarmill.rosuav.com.key 2048
$ openssl req -x509 -new -nodes -passin pass: -key sugarmill.rosuav.com.key -sha256 -days 3650 -out sugarmill.rosuav.com.pem -subj '/CN=sugarmill.rosuav.com'
$ cp sugarmill.rosuav.com.pem /usr/local/share/ca-certificates/
$ update-ca-certificates

This should be needed only very rarely and need not be automated.

Copy the root cert also to Gideon.

The root key remains in this directory and will only be accessible to the root user.

Generate the active cert
------------------------

TODO: Automate this. It will need to be scheduled to run regularly, based on remaining cert validity.

$ openssl genrsa -out db.rosuav.com.key -traditional 2048
$ openssl req -new -key db.rosuav.com.key -out db.rosuav.com.csr -subj '/CN=db.rosuav.com'
$ echo 'subjectAltName=DNS:ipv4.rosuav.com,DNS:sikorsky.rosuav.com' | openssl x509 -req -passin pass: -in db.rosuav.com.csr -CA root-ca.rosuav.com.pem -CAkey root-ca.rosuav.com.key -CAcreateserial -out db.rosuav.com.pem -days 90 -sha256 -extfile -
$ cp db.rosuav.com.{pem,key} /home/rosuav/stillebot/
$ chown rosuav: /home/rosuav/stillebot/db.rosuav.com.*
$ cp db.rosuav.com.pem /etc/postgresql/16/main/certificate.pem
$ cp db.rosuav.com.key /etc/postgresql/16/main/privkey.pem
$ chown postgres: /etc/postgresql/16/main/*.pem
$ systemctl reload postgresql
$ scp db.rosuav.com.{pem,key} root-ca.rosuav.com.{pem,key} gideon:
- and install them on Gideon too
