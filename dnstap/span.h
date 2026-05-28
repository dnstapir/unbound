/*
 * span.h -- intra-process query span tracing for DNS resolvers
 *
 * Each query is assigned a unique 64-bit trace_id at worker ingress
 * Lightweight CBOR frames are written to a Unix socket using the fstrm
 *
 * Copyright (c) 2025 hula
 */

#ifndef SPAN_H
#define SPAN_H

#include <stdint.h>
#include <stddef.h>
#include "dnstap/cbor_enc.h"

/* fstrm content-type */

#define SPAN_CONTENT_TYPE  "cbor-dns-span"

/* Maximum encoded size of a single span frame (bytes)
 * 512 accommodates SPAN_RRSET with RRSIG rdata and IPv6 in SPAN_INGRESS 
 */
#define SPAN_BUF_MAX  512

/* CBOR key constants */
/*
 */
#define SKEY_TRACE_ID     0   /* uint64 : unique query identifier        */
#define SKEY_SPAN_TYPE    1   /* uint16 : span_type_t value              */
#define SKEY_TS_NS        2   /* uint32 : monotonic ns; omitted when n/a */
#define SKEY_DETAIL       3   /* uint32 : span-specific numeric detail   */
#define SKEY_TRANSPORT    4   /* uint8  : span_transport_t               */
#define SKEY_SESSION      5   /* uint64 : TLS session hash; 0 = no TLS  */
#define SKEY_RESUMED      6   /* bool   : TLS session resumed (INGRESS only) */
#define SKEY_CLIENT_ADDR  7   /* bstr 4|16 : client source address       */
#define SKEY_DEST_ADDR    8   /* bstr 4|16 : local destination address   */
#define SKEY_PARENT_TID   9   /* uint64 : parent trace_id for link spans */
#define SKEY_CHILD_TID    10  /* uint64 : child trace_id for link spans  */
#define SKEY_REASON       11  /* uint8  : recurse_reason_t               */
#define SKEY_QNAME        12  /* bstr   : wire-format query name         */
#define SKEY_QTYPE        13  /* uint16 : query type                     */
#define SKEY_FLAGS        14  /* uint16 : context-dependent flags        */
#define SKEY_ORIG_RCODE   15  /* uint8  : rcode before RPZ rewrite       */
#define SKEY_POLICY_ZONE  16  /* bstr   : RPZ policy zone name           */
#define SKEY_RCODE        17  /* uint8  : final rcode to client          */
#define SKEY_ANCOUNT      18  /* uint16 : answer RR count                */
#define SKEY_RESP_SIZE    19  /* uint16 : wire size of response bytes    */
#define SKEY_EDNS_BITS    20  /* uint16 : e-rcode + client DNSSEC OK bit */
#define SKEY_EDNS         21  /* bool   : client sent EDNS0              */
#define SKEY_EDNS_BUFSZ   22  /* uint16 : client UDP payload size        */
#define SKEY_QID          23  /* uint16 : DNS wire query id              */
#define SKEY_WHY_BOGUS    24  /* uint8  : DNSSEC failure reason          */
#define SKEY_CHAIN_LEN    25  /* uint8  : DNSKEY/DS chain steps          */
#define SKEY_SOA_TTL      26  /* uint32 : SOA TTL (negative cache life)  */
#define SKEY_NSEC_TYPE    27  /* uint8  : 0=none 1=NSEC 2=NSEC3          */
#define SKEY_WILDCARD     28  /* bool   : wildcard synthesis             */
#define SKEY_UDP_SIZE     29  /* uint16 : size that caused truncation    */
#define SKEY_RETRY_COUNT  30  /* uint8  : upstream retries before answer */
#define SKEY_UPSTREAM_FL  31  /* uint8  : upstream AA/TC flags           */
#define SKEY_IP_VERSION   32  /* uint8  : 4 or 6                         */
#define SKEY_RD_CD_FLAGS  33  /* uint8  : RD=bit0, CD=bit1 from client   */
#define SKEY_RESTART_CNT  34  /* uint8  : CNAME/referral restart count   */
#define SKEY_ANSWER_TTL   35  /* uint32 : min TTL across answer section  */
#define SKEY_SECTION      36  /* uint8  : rrset_section_t                */
#define SKEY_QCLASS       37  /* uint16 : RR class (IN=1)                */
#define SKEY_RDATA        38  /* bstr   : single RR rdata (wire format)  */
#define SKEY_NET_ERROR    39  /* uint8  : NETEVENT_* error; 0 = no error */

/* span type enum */

/*
 * ts_ns convention: pass clock_gettime(CLOCK_MONOTONIC).tv_nsec where
 * latency is meaningful; pass 0 otherwise. Consumer treats 0 as absent.
 * Spans marked "clock" below are the points where a clock reading is taken.
 */
typedef enum {
    SPAN_INGRESS_CONN     = 0,   /* clock: trace anchor                   */
    SPAN_INGRESS_QUERY    = 1,
    SPAN_INGRESS_EDNS     = 2,
    SPAN_ACL              = 3,
    SPAN_LOCAL_ZONE_HIT   = 4,
    SPAN_RPZ_CLIENT       = 5,
    SPAN_CACHE_HIT        = 6,
    SPAN_CACHE_STALE_HIT  = 7,
    SPAN_RECURSE_SPAWN    = 8,
    SPAN_ITERATOR         = 9,   /* clock: RTT send/recv                  */
    SPAN_VALIDATOR        = 10,  /* clock: validation cost                */
    SPAN_RPZ_RESPONSE     = 11,
    SPAN_STALE_FALLBACK   = 12,  /* clock: timeout duration               */
    SPAN_CACHE_INSERT     = 13,
    SPAN_MESH_ATTACH      = 14,
    SPAN_EGRESS           = 15,  /* clock: total latency close            */
    SPAN_DNSSEC_CHAIN     = 16,
    SPAN_NEGATIVE         = 17,
    SPAN_TRUNCATED        = 18,
    SPAN_RRSET            = 19,
} span_type_t;


/* recursion reason enum */
typedef enum {
    RECURSE_REASON_NORMAL         = 0,
    RECURSE_REASON_STALE_REFRESH  = 1,
    RECURSE_REASON_PREFETCH       = 2,
    RECURSE_REASON_CNAME          = 3,
    RECURSE_REASON_DNAME          = 4,
} recurse_reason_t;


/* transport type enum */
typedef enum {
    SPAN_TRANSPORT_UDP  = 0,
    SPAN_TRANSPORT_TCP  = 1,
    SPAN_TRANSPORT_DOT  = 2,
    SPAN_TRANSPORT_DOH  = 3,
    SPAN_TRANSPORT_DOQ  = 4,
} span_transport_t;


/* DNSSEC bogus reason enum */
typedef enum {
    BOGUS_BAD_SIG         = 0,
    BOGUS_MISSING_RRSIG   = 1,
    BOGUS_EXPIRED         = 2,
    BOGUS_NSEC_MISSING    = 3,
    BOGUS_DNSKEY_MISSING  = 4,
    BOGUS_DS_MISMATCH     = 5,
} bogus_reason_t;


/* RRset section enum */
typedef enum {
    RRSET_SECTION_ANSWER     = 0,  /* normal post-resolution answer        */
    RRSET_SECTION_AUTH       = 1,  /* authority section                    */
    RRSET_SECTION_ADDITIONAL = 2,  /* additional section                   */
    RRSET_SECTION_PRE_RPZ    = 3,  /* original answer before RPZ rewrite;
                                    * emitted before SPAN_RPZ_RESPONSE,
                                    * independent of span-emit-rrsets      */
} rrset_section_t;


/* stream functions */

/* handle
 */
struct span_stream;

/* span_stream_open
 * connect to relay Unix socket, send fstrm START
 * On failure, tracing is silently disabled for this worker.
 */
struct span_stream *span_stream_open(const char *path);

/* span_stream_close
 * send fstrm STOP, close socket, free handle
 */
void span_stream_close(struct span_stream *s);


/* trace id */

/* span_new_trace_id
 * atomic increment of global counter
 * Called once in worker_handle_request
 * Called once per recursive subquery at attach_sub
 */
uint64_t span_new_trace_id(void);


/* span emitters */

/* SPAN_INGRESS_CONN
 *
 * Emitted at the very top of worker_handle_request(), before any parsing.
 * net_error is the NETEVENT_* value from the error parameter; 0 = no error.
 * If net_error != 0, no further spans follow for this trace_id.
 * ts_ns: clock_gettime(CLOCK_MONOTONIC).tv_nsec -- trace wall-clock anchor.
 */
void span_emit_ingress_conn(struct span_stream *s,
    uint64_t          trace_id,
    uint32_t          ts_ns,
    span_transport_t  transport,
    uint64_t          session_hash, /* FNV-1a of TLS session id, or ptr cast */
    int               resumed,      /* SSL_session_reused()                  */
    const void       *client_addr,
    size_t            client_addrlen,
    const void       *dest_addr,
    size_t            dest_addrlen,
    uint8_t           ip_version,
    int               net_error);


/* SPAN_INGRESS_QUERY
 *
 * Emitted after query_info_parse() succeeds. ts_ns=0; ordering relative
 */
void span_emit_ingress_query(struct span_stream *s,
    uint64_t        trace_id,
    uint16_t        qid,
    const uint8_t  *qname,
    size_t          qname_len,
    uint16_t        qtype,
    uint16_t        qclass,
    uint8_t         rd_cd_flags);


/* SPAN_INGRESS_EDNS
 *
 * Emitted after query_info_parse() succeeds. ts_ns=0; ordering relative
 */
void span_emit_ingress_edns(struct span_stream *s,
    uint64_t        trace_id,
    int             edns_present,
    uint16_t        edns_bufsize,
    uint16_t        edns_bits);


/* General-purpose span emitter
 *
 * Used for: SPAN_ACL, SPAN_LOCAL_ZONE_HIT, SPAN_CACHE_HIT,
 *           SPAN_CACHE_STALE_HIT, SPAN_CACHE_INSERT, SPAN_TRUNCATED,
 *           SPAN_VALIDATOR, SPAN_STALE_FALLBACK,
 *           SPAN_ITERATOR send (detail = fwd_mode),
 *           SPAN_DNSSEC_CHAIN (via wrapper), SPAN_NEGATIVE (via wrapper).
 *
 * Encodes a 4-key CBOR map: trace_id, span_type, ts_ns, detail.
 * The uniform 4-key map keeps the consumer decode path unconditional.
 *
 * Clock readings for INGRESS, EGRESS, ITERATOR send/recv,
 * VALIDATOR, STALE_FALLBACK. 
 * Pass ts_ns=0 when no clock reading
 *
 */
void span_emit_simple(struct span_stream *s,
    uint64_t     trace_id,
    span_type_t  type,
    uint32_t     ts_ns,
    uint32_t     detail);


/* SPAN_RECURSE_SPAWN, SPAN_MESH_ATTACH
 *
 * Link span parent to child trace_id relationship
 * 
 */
void span_emit_recurse(struct span_stream *s,
    uint64_t          parent_tid,
    uint64_t          child_tid,
    span_type_t       type,
    recurse_reason_t  reason,
    const uint8_t    *qname,
    size_t            qname_len,
    uint16_t          qtype,
    uint8_t           restart_count);


/* SPAN_ITERATOR (recv frame)
 */
void span_emit_iterator_recv(struct span_stream *s,
    uint64_t     trace_id,
    uint32_t     ts_ns,
    uint32_t     rtt_us,
    uint8_t      upstream_rcode,
    uint8_t      upstream_flags,  /* bit0=AA bit1=TC                    */
    const void  *upstream_addr,
    size_t       upstream_addrlen,
    uint8_t      retry_count);


/* SPAN_EGRESS
 */
void span_emit_egress(struct span_stream *s,
    uint64_t  trace_id,
    uint32_t  ts_ns,
    uint8_t   rcode,
    uint16_t  ancount,
    uint16_t  flags,
    uint16_t  resp_size,
    uint16_t  edns_bits,
    uint32_t  answer_ttl);


/* SPAN_RPZ_CLIENT, SPAN_RPZ_RESPONSE
 *
 * orig_rcode is 0 for client-side RPZ.
 *
 * For response-side, orig_rcode captures upstream rcode
 *
 * rewritten is packed into the high bit of action (bit15):
 *   SKEY_DETAIL = (rewritten << 15) | action
 * Keeps the map to 5 keys and avoids SKEY_RESUMED overload.
 */
void span_emit_rpz(struct span_stream *s,
    uint64_t     trace_id,
    span_type_t  type,
    uint16_t     trigger,
    uint16_t     action,      /* low 15 bits; bit15 = rewritten flag */
    uint8_t      orig_rcode,
    const char  *policy_zone);


/* SPAN_DNSSEC_CHAIN
 *
 * why_bogus meaningful when sec_status == BOGUS.
 * signed_zone correlates via trace_id to SPAN_VALIDATOR
 */
void span_emit_dnssec_chain(struct span_stream *s,
    uint64_t       trace_id,
    uint8_t        sec_status,
    bogus_reason_t why_bogus,
    uint8_t        chain_len);


/* SPAN_NEGATIVE
 *
 * NXDOMAIN vs NODATA: rcode=3 vs rcode=0 with empty answer.
 */
void span_emit_negative(struct span_stream *s,
    uint64_t  trace_id,
    uint8_t   rcode,
    uint32_t  soa_ttl,
    uint8_t   nsec_type,
    int       wildcard);


/* SPAN_RRSET
 *
 * Emit points:
 *
 *   (A) daemon/worker.c, after comm_point_send_reply(), iterating
 *       rep->rrsets[0..rrset_count-1]. Gated by cfg->span_emit_rrsets.
 *       section = RRSET_SECTION_ANSWER / AUTH / ADDITIONAL.
 *
 *   (B) respip/respip.c, before rpz_apply_response_trigger(), iterating
 *       qstate->return_msg->rep->rrsets. NOT gated by span_emit_rrsets --
 *       pre-RPZ rrset content is security-relevant and always captured
 *       when RPZ fires. section = RRSET_SECTION_PRE_RPZ.
 *
 * rdata is wire-format rdata of a single RR. For RRsets with multiple
 * RRs (round-robin A, multiple MX), emit one SPAN_RRSET per RR.
 */
void span_emit_rrset(struct span_stream *s,
    uint64_t          trace_id,
    rrset_section_t   section,
    const uint8_t    *owner,       /* wire-format owner name   */
    size_t            owner_len,
    uint16_t          rrtype,
    uint16_t          rrclass,
    uint32_t          ttl,
    const uint8_t    *rdata,       /* wire-format rdata        */
    size_t            rdata_len);

#endif /* SPAN_H */
