FROM docker.io/fedora:40

RUN dnf -y update && dnf -y install unbound openssl bind-utils

ADD entrypoint.sh /

EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 443/tcp
EXPOSE 853/tcp

COPY local.d/* /etc/unbound/local.d/

ENTRYPOINT ["sh", "/entrypoint.sh"]
