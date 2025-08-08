//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"

#include "vortex.h"

#ifndef __BPF_VORTEX_MAPS_C
#define __BPF_VORTEX_MAPS_C

/*
 * Map to store events for user space consumption.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB buffer */
    __type(value, struct event);
} events SEC(".maps");

/*
 * Map to control which TGIDs are traced. A key of TGID_ENABLE_ALL means all
 * TGIDs are traced. Otherwise, only trace whatever's in the map.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} tgids_to_trace SEC(".maps");

/*
 * Map to store the user buffer pointer for SSL_read. The key is the PID/TGID,
 * and the value is a pointer to the user buffer.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, char *);
} ssl_read_map SEC(".maps");

/*
 * Map to track SSL handshakes. The key is the PID/TGID, and the value is a
 * simple byte (not used, just to indicate that the handshake is in progress).
 * This map is used to determine if we should trace SSL_write/SSL_read.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} ssl_handshakes SEC(".maps");

/*
 * The following struct defs are for associating SSL_writes and SSL_reads to
 * socket information. This makes it limited to apps that are "BIO-native",
 * or those that use their TLS/SSL libraries to handle the networking
 * alongside crypto.
 *
 * Unfortunately, this won't support "BIO-custom apps", or those that
 * only use the TLS/SSL libraries for crypto, and handle networking by
 * themselves.
 *
 * Anyway, this is easier to implement than using offsets, which is very
 * error-prone and requires a lot of maintenance. We might need to do offsets
 * in the future, for those BIO-custom apps.
 */

/* Callstack context information. */
struct ssl_callstack_ctx {
    uintptr_t buf; /* instead of (char *), which bpf2go doesn't support */
    int len;
};

/* Active on SSL_write entry, removed on SSL_write exit. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct ssl_callstack_ctx);
} ssl_write_callstack SEC(".maps");

/* Active on SSL_read entry, removed on SSL_read exit. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct ssl_callstack_ctx);
} ssl_read_callstack SEC(".maps");

#endif /* __BPF_VORTEX_MAPS_C */
