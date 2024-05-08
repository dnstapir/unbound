#!/bin/sh

if [ ! -f /etc/pki/tls/private/unbound.pem ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out /etc/pki/tls/private/unbound.pem
    chown unbound /etc/pki/tls/private/unbound.pem
fi


if [ ! -f /etc/pki/tls/certs/unbound.pem ]; then
    openssl req -new -x509 \
        -key /etc/pki/tls/private/unbound.pem \
        -out /etc/pki/tls/certs/unbound.pem \
        -subj "/CN=unbound" \
        -days 1000
fi

/usr/sbin/unbound -d
