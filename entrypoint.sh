#!/bin/sh

if [ ! -f /etc/unbound/unbound_control.key ]; then
    unbound-control-setup
fi

/usr/sbin/unbound -d
