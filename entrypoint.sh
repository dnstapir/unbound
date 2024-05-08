#!/bin/sh

if [ ! -f /config/unbound_control.key ]; then
    unbound-control-setup
fi

if [ ! -f /config/root.key ]; then
    unbound-anchor
fi

if [ ! -f /config/tls_service.key ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out /config/tls_service.key
    chown unbound /config/tls_service.key
fi


if [ ! -f /config/tls_service.crt ]; then
    openssl req -new -x509 \
        -key /config/tls_service.key \
        -out /config/tls_service.crt \
        -subj "/CN=unbound" \
        -days 1000
fi

/usr/local/sbin/unbound -d
