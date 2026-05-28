/*
 * cbor_enc.h -- minimal CBOR encoder (RFC 8949)
 *
 * Encodes integer-keyed maps with uint, bstr, and bool values into a
 * caller-supplied buffer. No heap allocation. No dependencies.
 *
 * Only the subset required for DNS span frames is implemented:
 *   - Definite-length maps
 *   - Unsigned integers (major type 0)
 *   - Byte strings  (major type 2)
 *   - Simple values: true/false (major type 7)
 *
 * Copyright (c) 2025 hula
 *
 */

#ifndef CBOR_ENC_H
#define CBOR_ENC_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Encoder state */
typedef struct cbor_enc {
    uint8_t *buf;   /* output buffer, caller-supplied */
    size_t   cap;   /* buffer capacity in bytes */
    size_t   pos;   /* current write position */
    int      err;   /* non-zero if buffer overflowed */
} cbor_enc_t;


/* Major type tags (upper 3 bits of initial byte) */
#define CBOR_UINT   (0x00u)
#define CBOR_BSTR   (0x40u)
#define CBOR_MAP    (0xa0u)
#define CBOR_SIMPLE (0xe0u)


/* Simple values */
#define CBOR_FALSE  (0xf4u)
#define CBOR_TRUE   (0xf5u)


/* Additional thresholds */
#define CBOR_AI_1   (24u)   /* value in following 1 byte */
#define CBOR_AI_2   (25u)   /* value in following 2 bytes */
#define CBOR_AI_4   (26u)   /* value in following 4 bytes */
#define CBOR_AI_8   (27u)   /* value in following 8 bytes */


/* Internal helpers 
 *
 * _cbor_write1
 *
 */
static inline void
_cbor_write1(cbor_enc_t *e, uint8_t b)
{
    if(e->pos < e->cap)
        e->buf[e->pos] = b;
    else
        e->err = 1;
    e->pos++;
}


/* _cbor_head
 *
 */
static inline void
_cbor_head(cbor_enc_t *e, uint8_t major, uint64_t val)
{
    if(val <= 23u) {
        _cbor_write1(e, major | (uint8_t)val);
    } else if(val <= 0xffu) {
        _cbor_write1(e, major | CBOR_AI_1);
        _cbor_write1(e, (uint8_t)val);
    } else if(val <= 0xffffu) {
        _cbor_write1(e, major | CBOR_AI_2);
        _cbor_write1(e, (uint8_t)(val >> 8));
        _cbor_write1(e, (uint8_t)(val));
    } else if(val <= 0xffffffffu) {
        _cbor_write1(e, major | CBOR_AI_4);
        _cbor_write1(e, (uint8_t)(val >> 24));
        _cbor_write1(e, (uint8_t)(val >> 16));
        _cbor_write1(e, (uint8_t)(val >>  8));
        _cbor_write1(e, (uint8_t)(val));
    } else {
        _cbor_write1(e, major | CBOR_AI_8);
        _cbor_write1(e, (uint8_t)(val >> 56));
        _cbor_write1(e, (uint8_t)(val >> 48));
        _cbor_write1(e, (uint8_t)(val >> 40));
        _cbor_write1(e, (uint8_t)(val >> 32));
        _cbor_write1(e, (uint8_t)(val >> 24));
        _cbor_write1(e, (uint8_t)(val >> 16));
        _cbor_write1(e, (uint8_t)(val >>  8));
        _cbor_write1(e, (uint8_t)(val));
    }
}


/* public API */

/*
 * cbor_init
 * initialise encoder against caller-supplied buffer.
 */
static inline void
cbor_init(cbor_enc_t *e, uint8_t *buf, size_t cap)
{
    e->buf = buf;
    e->cap = cap;
    e->pos = 0;
    e->err = 0;
}


/* cbor_map
 * open a definite-length map with `count` key/value pairs
 * caller must emit exactly `count * 2` items (keys and values) afterward
 */
static inline void
cbor_map(cbor_enc_t *e, size_t count)
{
    _cbor_head(e, CBOR_MAP, (uint64_t)count);
}


/* cbor_uint
 * encode an unsigned integer
 * used for both map keys and uint values
 */
static inline void
cbor_uint(cbor_enc_t *e, uint64_t val)
{
    _cbor_head(e, CBOR_UINT, val);
}


/* cbor_bstr
 * encode a byte string
 * `data` may be NULL only if `len` is 0
 */
static inline void
cbor_bstr(cbor_enc_t *e, const void *data, size_t len)
{
    _cbor_head(e, CBOR_BSTR, (uint64_t)len);
    if(len == 0 || data == NULL)
        return;
    if(e->pos + len <= e->cap)
        memcpy(e->buf + e->pos, data, len);
    else
        e->err = 1;
    e->pos += len;
}


/* cbor_bool
 * encode a boolean simple value
 */
static inline void
cbor_bool(cbor_enc_t *e, int val)
{
    _cbor_write1(e, val ? CBOR_TRUE : CBOR_FALSE);
}


/* cbor_len
 * return number of bytes written so far
 * Valid even if err is set (reflects bytes that would have been written)
 * Use cbor_ok() to check for overflow before consuming cbor_len() bytes
 */
static inline size_t
cbor_len(const cbor_enc_t *e)
{
    return e->pos;
}


/* cbor_ok
 * return non-zero if encoding succeeded without overflow.
 */
static inline int
cbor_ok(const cbor_enc_t *e)
{
    return !e->err && (e->pos <= e->cap);
}

#endif /* CBOR_ENC_H */
