/*
 * span.c 
 * query span tracing implementation
 *
 * Copyright (c) 2025 hula
 *
 * See span.h for design constraints and API documentation.
 */

#include "config.h"
#include "dnstap/span.h"
#include "dnstap/dnstap_fstrm.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdatomic.h>
#include <arpa/inet.h>


/* global trace_id */

/* span_trace_counter
 */
static _Atomic uint64_t span_trace_counter = 1;

/* span_new_trace_id 
 */
uint64_t
span_new_trace_id(void)
{
    return atomic_fetch_add_explicit(&span_trace_counter, 1,
                                     memory_order_relaxed);
}


/* internal I/O helpers*/ 

/* stream handle 
*/
struct span_stream {
    int fd;
};

/* span_write_all
 */
static int
span_write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/* span_write_frame
 * Write a data frame: 4-byte big-endian length prefix + CBOR payload
 * Silently drops the frame on write error (non-blocking telemetry)
 */
static void
span_write_frame(struct span_stream *s, const uint8_t *buf, size_t len)
{
    uint32_t nlen = htonl((uint32_t)len);
    /* Two writes; kernel will coalesce on loopback Unix socket. */
    if (span_write_all(s->fd, &nlen, 4) < 0) return;
    span_write_all(s->fd, buf, len);
}


/* stream functions */

/* span_stream_open
 * open the span stream on top of fstrm
 */
struct span_stream *
span_stream_open(const char *path)
{
    struct span_stream *s;
    struct sockaddr_un  sa;
    size_t              flen = 0;
    void               *frame;

    s = malloc(sizeof(*s));
    if (!s) return NULL;

    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);

    s->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s->fd < 0) { free(s); return NULL; }

    if (connect(s->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(s->fd); free(s); return NULL;
    }

    /* Send fstrm START control frame advertising our content-type
     * fstrm_create_control_frame_start() is from dnstap_fstrm.c
     */
    frame = fstrm_create_control_frame_start(SPAN_CONTENT_TYPE, &flen);
    if (!frame) { close(s->fd); free(s); return NULL; }
    span_write_all(s->fd, frame, flen);
    free(frame);

    return s;
}

/* span_stream_close
 */
void
span_stream_close(struct span_stream *s)
{
    size_t  flen = 0;
    void   *frame;

    if (!s) return;
    frame = fstrm_create_control_frame_stop(&flen);
    if (frame) {
        span_write_all(s->fd, frame, flen);
        free(frame);
    }
    close(s->fd);
    free(s);
}


/* span emitters */

/* span_emit_ingress
 */
void
span_emit_ingress_conn(struct span_stream *s,
    uint64_t          trace_id,
    uint32_t          ts_ns,
    span_transport_t  transport,
    uint64_t          session_hash,
    int               resumed,
    const void       *client_addr,
    size_t            client_addrlen,
    const void       *dest_addr,
    size_t            dest_addrlen,
    uint8_t           ip_version,
    int               net_error)
{
    uint8_t     buf[SPAN_BUF_MAX];
    cbor_enc_t  e;

    if (!s) return;

    cbor_init(&e, buf, sizeof(buf));
    cbor_map(&e, 10);

    cbor_uint(&e, SKEY_TRACE_ID);    cbor_uint(&e, trace_id);
    cbor_uint(&e, SKEY_SPAN_TYPE);   cbor_uint(&e, SPAN_INGRESS_CONN);
    cbor_uint(&e, SKEY_TS_NS);       cbor_uint(&e, ts_ns);
    cbor_uint(&e, SKEY_TRANSPORT);   cbor_uint(&e, (uint64_t)transport);
    cbor_uint(&e, SKEY_SESSION);     cbor_uint(&e, session_hash);
    cbor_uint(&e, SKEY_RESUMED);     cbor_bool(&e, resumed);
    cbor_uint(&e, SKEY_CLIENT_ADDR); cbor_bstr(&e, client_addr, client_addrlen);
    cbor_uint(&e, SKEY_DEST_ADDR);   cbor_bstr(&e, dest_addr,   dest_addrlen);
    cbor_uint(&e, SKEY_IP_VERSION);  cbor_uint(&e, ip_version);
    cbor_uint(&e, SKEY_NET_ERROR);   cbor_uint(&e, net_error);

    if (cbor_ok(&e)) span_write_frame(s, buf, cbor_len(&e));
}


/* span_emit_ingress
 */
void
span_emit_ingress_query(struct span_stream *s,
    uint64_t          trace_id,
    uint16_t          qid,
    const uint8_t    *qname,
    size_t            qname_len,
    uint16_t          qtype,
    uint16_t          qclass,
    uint8_t           rd_cd_flags)
{
    uint8_t     buf[SPAN_BUF_MAX];
    cbor_enc_t  e;

    if (!s) return;

    cbor_init(&e, buf, sizeof(buf));
    cbor_map(&e, 8);

    cbor_uint(&e, SKEY_TRACE_ID);    cbor_uint(&e, trace_id);
    cbor_uint(&e, SKEY_SPAN_TYPE);   cbor_uint(&e, SPAN_INGRESS_QUERY);
    cbor_uint(&e, SKEY_TS_NS);       cbor_uint(&e, 0);
    cbor_uint(&e, SKEY_QID);         cbor_uint(&e, qid);
    cbor_uint(&e, SKEY_QNAME);       cbor_bstr(&e, qname, qname_len);
    cbor_uint(&e, SKEY_QTYPE);       cbor_uint(&e, qtype);
    cbor_uint(&e, SKEY_QCLASS);      cbor_uint(&e, qclass);
    cbor_uint(&e, SKEY_RD_CD_FLAGS); cbor_uint(&e, rd_cd_flags);

    if (cbor_ok(&e)) span_write_frame(s, buf, cbor_len(&e));
}


/* SPAN_INGRESS_EDNS
 * 
 * Emitted after query_info_parse() succeeds. ts_ns=0; ordering relative
 */
void span_emit_ingress_edns(struct span_stream *s,
    uint64_t        trace_id,
    int             edns_present,
    uint16_t        edns_bufsize,
    uint16_t        edns_bits)
{
    uint8_t     buf[SPAN_BUF_MAX];
    cbor_enc_t  e;

    if (!s || !trace_id) return;

    cbor_init(&e, buf, sizeof(buf));
    cbor_map_begin(&e, 6);

    cbor_uint(&e, SKEY_TRACE_ID);   cbor_uint(&e, trace_id);
    cbor_uint(&e, SKEY_SPAN_TYPE);  cbor_uint(&e, SPAN_INGRESS_EDNS);
    cbor_uint(&e, SKEY_TS_NS);      cbor_uint(&e, 0);
    cbor_uint(&e, SKEY_EDNS);       cbor_bool(&e, edns_present);
    cbor_uint(&e, SKEY_EDNS_BUFSZ); cbor_uint(&e, edns_bufsize);
    cbor_uint(&e, SKEY_EDNS_BITS);  cbor_uint(&e, edns_bits);

    if (cbor_ok(&e)) span_write_frame(s, buf, cbor_len(&e));
}


/* span_emit_simple
 */
void
span_emit_simple(struct span_stream *s,
    uint64_t     trace_id,
    span_type_t  type,
    uint32_t     ts_ns,
    uint32_t     detail)
{
    uint8_t     buf[SPAN_BUF_MAX];
    cbor_enc_t  e;

    if (!s || !trace_id) return;

    cbor_init(&e, buf, sizeof(buf));
    cbor_map(&e, 4);

    cbor_uint(&e, SKEY_TRACE_ID);  cbor_uint(&e, trace_id);
    cbor_uint(&e, SKEY_SPAN_TYPE); cbor_uint(&e, (uint64_t)type);
    cbor_uint(&e, SKEY_TS_NS);     cbor_uint(&e, ts_ns);
    cbor_uint(&e, SKEY_DETAIL);    cbor_uint(&e, detail);

    if (cbor_ok(&e)) span_write_frame(s, buf, cbor_len(&e));
}

/* span_emit_recurse
 */
void
span_emit_recurse(struct span_stream *s,
    uint64_t          parent_tid,
    uint64_t          child_tid,
    span_type_t       type,
    recurse_reason_t  reason,
    const uint8_t    *qname,
    size_t            qname_len,
    uint16_t          qtype,
    uint8_t           restart_count)
{
    uint8_t     buf[SPAN_BUF_MAX];
    cbor_enc_t  e;

    if (!s || !parent_tid) return;

    cbor_init(&e, buf, sizeof(buf));
    cbor_map(&e, 8);

    cbor_uint(&e, SKEY_TRACE_ID);    cbor_uint(&e, parent_tid);
    cbor_uint(&e, SKEY_SPAN_TYPE);   cbor_uint(&e, (uint64_t)type);
    cbor_uint(&e, SKEY_PARENT_TID);  cbor_uint(&e, parent_tid);
    cbor_uint(&e, SKEY_CHILD_TID);   cbor_uint(&e, child_tid);
    cbor_uint(&e, SKEY_REASON);      cbor_uint(&e, (uint64_t)reason);
    cbor_uint(&e, SKEY_QNAME);       cbor_bstr(&e, qname, qname_len);
    cbor_uint(&e, SKEY_QTYPE);       cbor_uint(&e, qtype);
    cbor_uint(&e, SKEY_RESTART_CNT); cbor_uint(&e, restart_count);

    if (cbor_ok(&e)) span_write_frame(s, buf, cbor_len(&e));
}

/* span_emit_iterator_recv
 */
void
span_emit_iterator_recv(struct span_stream *s,
    uint64_t     trace_id,
    uint32_t     ts_ns,
    uint32_t     rtt_us,
    uint8_t      upstream_rcode,
    uint8_t      upstream_flags,
    const void  *upstream_addr,
    size_t       upstream_addrlen,
    uint8_t      retry_count)
{
    uint8_t     buf[SPAN_BUF_MAX];
    cbor_enc_t  e;

    if (!s || !trace_id) return;

    cbor_init(&e, buf, sizeof(buf));
    cbor_map(&e, 8);

    cbor_uint(&e, SKEY_TRACE_ID);    cbor_uint(&e, trace_id);
    cbor_uint(&e, SKEY_SPAN_TYPE);   cbor_uint(&e, SPAN_ITERATOR);
    cbor_uint(&e, SKEY_TS_NS);       cbor_uint(&e, ts_ns);
    cbor_uint(&e, SKEY_DETAIL);      cbor_uint(&e, rtt_us);
    cbor_uint(&e, SKEY_RCODE);       cbor_uint(&e, upstream_rcode);
    cbor_uint(&e, SKEY_UPSTREAM_FL); cbor_uint(&e, upstream_flags);
    cbor_uint(&e, SKEY_DEST_ADDR);   cbor_bstr(&e, upstream_addr,
                                                    upstream_addrlen);
    cbor_uint(&e, SKEY_RETRY_COUNT); cbor_uint(&e, retry_count);

    if (cbor_ok(&e)) span_write_frame(s, buf, cbor_len(&e));
}

/* span_emit_egress
 */
void
span_emit_egress(struct span_stream *s,
    uint64_t  trace_id,
    uint32_t  ts_ns,
    uint8_t   rcode,
    uint16_t  ancount,
    uint16_t  flags,
    uint16_t  resp_size,
    uint16_t  edns_bits,
    uint32_t  answer_ttl)
{
    uint8_t     buf[SPAN_BUF_MAX];
    cbor_enc_t  e;

    if (!s || !trace_id) return;

    cbor_init(&e, buf, sizeof(buf));
    cbor_map(&e, 9);

    cbor_uint(&e, SKEY_TRACE_ID);   cbor_uint(&e, trace_id);
    cbor_uint(&e, SKEY_SPAN_TYPE);  cbor_uint(&e, SPAN_EGRESS);
    cbor_uint(&e, SKEY_TS_NS);      cbor_uint(&e, ts_ns);
    cbor_uint(&e, SKEY_RCODE);      cbor_uint(&e, rcode);
    cbor_uint(&e, SKEY_ANCOUNT);    cbor_uint(&e, ancount);
    cbor_uint(&e, SKEY_FLAGS);      cbor_uint(&e, flags);
    cbor_uint(&e, SKEY_RESP_SIZE);  cbor_uint(&e, resp_size);
    cbor_uint(&e, SKEY_EDNS_BITS);  cbor_bool(&e, edns_bits);
    cbor_uint(&e, SKEY_ANSWER_TTL); cbor_uint(&e, answer_ttl);

    if (cbor_ok(&e)) span_write_frame(s, buf, cbor_len(&e));
}

/* span_emit_rpz
 */
void
span_emit_rpz(struct span_stream *s,
    uint64_t     trace_id,
    span_type_t  type,
    uint16_t     trigger,
    uint16_t     action,
    uint8_t      orig_rcode,
    const char  *policy_zone)
{
    uint8_t     buf[SPAN_BUF_MAX];
    cbor_enc_t  e;

    if (!s || !trace_id) return;

    /* rewritten flag is packed into bit15 of action by the caller:
     *   action = (rewritten ? 0x8000u : 0) | rpz_action_value  */
    cbor_init(&e, buf, sizeof(buf));
    cbor_map(&e, 6);

    cbor_uint(&e, SKEY_TRACE_ID);    cbor_uint(&e, trace_id);
    cbor_uint(&e, SKEY_SPAN_TYPE);   cbor_uint(&e, (uint64_t)type);
    cbor_uint(&e, SKEY_FLAGS);       cbor_uint(&e, trigger);
    cbor_uint(&e, SKEY_DETAIL);      cbor_uint(&e, action);
    cbor_uint(&e, SKEY_ORIG_RCODE);  cbor_uint(&e, orig_rcode);
    cbor_uint(&e, SKEY_POLICY_ZONE); cbor_bstr(&e, policy_zone,
                                        policy_zone ? strlen(policy_zone) : 0);

    if (cbor_ok(&e)) span_write_frame(s, buf, cbor_len(&e));
}

/* span_emit_dnssec_chain
 */
void
span_emit_dnssec_chain(struct span_stream *s,
    uint64_t       trace_id,
    uint8_t        sec_status,
    bogus_reason_t why_bogus,
    uint8_t        chain_len)
{
    uint8_t     buf[SPAN_BUF_MAX];
    cbor_enc_t  e;

    if (!s || !trace_id) return;

    cbor_init(&e, buf, sizeof(buf));
    cbor_map(&e, 5);

    cbor_uint(&e, SKEY_TRACE_ID);   cbor_uint(&e, trace_id);
    cbor_uint(&e, SKEY_SPAN_TYPE);  cbor_uint(&e, SPAN_DNSSEC_CHAIN);
    cbor_uint(&e, SKEY_DETAIL);     cbor_uint(&e, sec_status);
    cbor_uint(&e, SKEY_WHY_BOGUS);  cbor_uint(&e, (uint64_t)why_bogus);
    cbor_uint(&e, SKEY_CHAIN_LEN);  cbor_uint(&e, chain_len);

    if (cbor_ok(&e)) span_write_frame(s, buf, cbor_len(&e));
}

/* span_emit_negative
 */
void
span_emit_negative(struct span_stream *s,
    uint64_t  trace_id,
    uint8_t   rcode,
    uint32_t  soa_ttl,
    uint8_t   nsec_type,
    int       wildcard)
{
    uint8_t     buf[SPAN_BUF_MAX];
    cbor_enc_t  e;

    if (!s || !trace_id) return;

    cbor_init(&e, buf, sizeof(buf));
    cbor_map(&e, 6);

    cbor_uint(&e, SKEY_TRACE_ID);   cbor_uint(&e, trace_id);
    cbor_uint(&e, SKEY_SPAN_TYPE);  cbor_uint(&e, SPAN_NEGATIVE);
    cbor_uint(&e, SKEY_RCODE);      cbor_uint(&e, rcode);
    cbor_uint(&e, SKEY_SOA_TTL);    cbor_uint(&e, soa_ttl);
    cbor_uint(&e, SKEY_NSEC_TYPE);  cbor_uint(&e, nsec_type);
    cbor_uint(&e, SKEY_WILDCARD);   cbor_bool(&e, wildcard);

    if (cbor_ok(&e)) span_write_frame(s, buf, cbor_len(&e));
}

/* span_emit_rrset
 */
void
span_emit_rrset(struct span_stream *s,
    uint64_t          trace_id,
    rrset_section_t   section,
    const uint8_t    *owner,
    size_t            owner_len,
    uint16_t          rrtype,
    uint16_t          rrclass,
    uint32_t          ttl,
    const uint8_t    *rdata,
    size_t            rdata_len)
{
    uint8_t     buf[SPAN_BUF_MAX];
    cbor_enc_t  e;

    if (!s || !trace_id) return;

    cbor_init(&e, buf, sizeof(buf));
    cbor_map(&e, 9);

    cbor_uint(&e, SKEY_TRACE_ID);  cbor_uint(&e, trace_id);
    cbor_uint(&e, SKEY_SPAN_TYPE); cbor_uint(&e, SPAN_RRSET);
    cbor_uint(&e, SKEY_TS_NS);     cbor_uint(&e, 0);
    cbor_uint(&e, SKEY_SECTION);   cbor_uint(&e, (uint64_t)section);
    cbor_uint(&e, SKEY_QNAME);     cbor_bstr(&e, owner,  owner_len);
    cbor_uint(&e, SKEY_QTYPE);     cbor_uint(&e, rrtype);
    cbor_uint(&e, SKEY_QCLASS);    cbor_uint(&e, rrclass);
    cbor_uint(&e, SKEY_DETAIL);    cbor_uint(&e, ttl);
    cbor_uint(&e, SKEY_RDATA);     cbor_bstr(&e, rdata,  rdata_len);

    if (cbor_ok(&e)) span_write_frame(s, buf, cbor_len(&e));
}
