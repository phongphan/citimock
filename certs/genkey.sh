openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout server_pk.key -out server_cert.crt -config csr.conf
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout client_pk.key -out client_cert.crt -config csr.conf
