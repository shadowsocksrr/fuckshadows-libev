/*
 * Copyright (c) 2014, Dustin Lundquist <dustin@null-ptr.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>

#include <ares.h>

#include <ev.h>

#include <libcork/core.h>

#include "resolv.h"
#include "utils.h"
#include "netutils.h"

#define MAX_RESOLVE_CTX_NUM 2048

/*
 * Implement DNS resolution interface using libc-ares
 */

struct resolv_ctx {
    struct ev_io io;
    ares_socket_t socket;
    int is_used;
};

struct resolv_query {
    int requests[2];
    size_t response_count;
    struct sockaddr **responses;

    void (*client_cb)(struct sockaddr *, void *);
    void (*free_cb)(void *);

    uint16_t port;

    void *data;
};

extern int verbose;

/*
 * current used resolv_ctx number
 * to determine whether the channel is idle
 */
static volatile int current_ctx_num;

/* reusable resolv_ctx collection */
static struct resolv_ctx resolv_ctxs[MAX_RESOLVE_CTX_NUM];

/* global resolv channel */
static ares_channel default_channel;

/* global timer being used to process fd */
static struct ev_timer default_timer;

/* the event loop */
static struct ev_loop *default_loop;

static const int MODE_IPV4_ONLY  = 0;
static const int MODE_IPV6_ONLY  = 1;
static const int MODE_IPV4_FIRST = 2;
static const int MODE_IPV6_FIRST = 3;
static int resolv_mode           = 0;

static void ares_io_handler(struct ev_loop *, struct ev_io *, int);
static void ares_fd_process_cb(struct ev_loop *, struct ev_timer *, int);
static void ares_resolv_sock_state_cb(void *, ares_socket_t, int, int);
static int ares_resolv_sock_config_cb(ares_socket_t, int, void *);
static int ares_resolv_sock_cb(ares_socket_t, int, void *);

static void dns_query_v4_cb(void *, int, int, struct hostent *);
static void dns_query_v6_cb(void *, int, int, struct hostent *);

static void process_client_callback(struct resolv_query *);
static inline int all_requests_are_null(struct resolv_query *);
static struct sockaddr *choose_ipv4_first(struct resolv_query *);
static struct sockaddr *choose_ipv6_first(struct resolv_query *);
static struct sockaddr *choose_any(struct resolv_query *);

static void find_resolv_ctx(ares_socket_t, struct resolv_ctx **);
static void cleanup_resolv_ctxs();
static void init_resolv_ctxs();
static void adjust_fd_process_timer();

/*
 * IO events callback
 */
static void
ares_io_handler(EV_P_ ev_io *w, int revents)
{
    ares_process_fd(default_channel,
                    (revents & EV_READ) ? w->fd : ARES_SOCKET_BAD,
                    (revents & EV_WRITE) ? w->fd : ARES_SOCKET_BAD);
}

int
resolv_init(struct ev_loop *loop, char *nameservers, int ipv6first)
{
    int status  = 0;
    int optmask = 0;

    if (ipv6first)
        resolv_mode = MODE_IPV6_FIRST;
    else
        resolv_mode = MODE_IPV4_FIRST;

    default_loop    = loop;
    current_ctx_num = 0;

    if ((status = ares_library_init(ARES_LIB_INIT_ALL)) != ARES_SUCCESS) {
        LOGE("c-ares error: %s", ares_strerror(status));
        FATAL("failed to initialize c-ares");
    }

    struct ares_options option;

    optmask             |= ARES_OPT_SOCK_STATE_CB;
    option.sock_state_cb = ares_resolv_sock_state_cb;
    optmask             |= ARES_OPT_TIMEOUTMS;
    option.timeout       = 3 * 1000;
    optmask             |= ARES_OPT_TRIES;
    option.tries         = 2;

    status = ares_init_options(&default_channel, &option, optmask);

    if (status != ARES_SUCCESS) {
        LOGE("c-ares error: %s", ares_strerror(status));
        FATAL("failed to initialize c-ares");
    }

    if (nameservers != NULL) {
#if ARES_VERSION_MINOR >= 11
        status = ares_set_servers_ports_csv(default_channel, nameservers);
#else
        status = ares_set_servers_csv(default_channel, nameservers);
#endif
    }

    if (status != ARES_SUCCESS) {
        LOGE("c-ares error: %s", ares_strerror(status));
        FATAL("failed to set nameservers");
    }

    ares_set_socket_configure_callback(default_channel,
                                       ares_resolv_sock_config_cb, NULL);

    ares_set_socket_callback(default_channel,
                             ares_resolv_sock_cb, NULL);

    ev_timer_init(&default_timer, ares_fd_process_cb, 0.0, 0.0);

    init_resolv_ctxs();

    return 0;
}

void
resolv_shutdown(struct ev_loop *loop)
{
    ares_cancel(default_channel);
    ares_destroy(default_channel);
    if (ev_is_active(&default_timer)) {
        ev_timer_stop(default_loop, &default_timer);
        ev_timer_set(&default_timer, 0., 0.);
    }
    cleanup_resolv_ctxs();
    ares_library_cleanup();
}

struct resolv_query *
resolv_start(const char *hostname, uint16_t port,
             void (*client_cb)(struct sockaddr *, void *),
             void (*free_cb)(void *), void *data)
{
    /*
     * Wrap c-ares's call back in our own
     */

    struct resolv_query *query = ss_malloc(sizeof(struct resolv_query));

    if (query == NULL) {
        LOGE("failed to allocate memory for DNS query callback data.");
        return NULL;
    }

    memset(query, 0, sizeof(struct resolv_query));

    query->port           = port;
    query->client_cb      = client_cb;
    query->response_count = 0;
    query->responses      = NULL;
    query->data           = data;
    query->free_cb        = free_cb;

    /* Submit A and AAAA requests */
    if (resolv_mode != MODE_IPV6_ONLY) {
        ares_gethostbyname(default_channel, hostname, AF_INET, dns_query_v4_cb, query);
        query->requests[0] = AF_INET;
    }

    if (resolv_mode != MODE_IPV4_ONLY) {
        ares_gethostbyname(default_channel, hostname, AF_INET6, dns_query_v6_cb, query);
        query->requests[1] = AF_INET6;
    }

    return query;
}

/*
 * Wrapper for client callback we provide to c-ares
 */
static void
dns_query_v4_cb(void *arg, int status, int timeouts, struct hostent *he)
{
    int i, n;
    struct resolv_query *query = (struct resolv_query *)arg;

    if (status == ARES_EDESTRUCTION) {
        return;
    }

    if (!he || status != ARES_SUCCESS) {
        if (verbose) {
            LOGI("failed to lookup v4 address %s", ares_strerror(status));
        }
        goto CLEANUP;
    }

    if (verbose) {
        LOGI("found address name v4 address %s", he->h_name);
    }

    n = 0;
    while (he->h_addr_list[n])
        n++;

    if (n > 0) {
        struct sockaddr **new_responses = ss_realloc(query->responses,
                                                     (query->response_count + n)
                                                     * sizeof(struct sockaddr *));

        if (new_responses == NULL) {
            LOGE("failed to allocate memory for additional DNS responses");
        } else {
            query->responses = new_responses;

            for (i = 0; i < n; i++) {
                struct sockaddr_in *sa = ss_malloc(sizeof(struct sockaddr_in));
                memset(sa, 0, sizeof(struct sockaddr_in));
                sa->sin_family = AF_INET;
                sa->sin_port   = query->port;
                memcpy(&sa->sin_addr, he->h_addr_list[i], he->h_length);

                query->responses[query->response_count] = (struct sockaddr *)sa;
                if (query->responses[query->response_count] == NULL) {
                    LOGE("failed to allocate memory for DNS query result address");
                } else {
                    query->response_count++;
                }
            }
        }
    }

CLEANUP:

    query->requests[0] = 0; /* mark A query as being completed */

    /* Once all requests have completed, call client callback */
    if (all_requests_are_null(query)) {
        return process_client_callback(query);
    }
}

static void
dns_query_v6_cb(void *arg, int status, int timeouts, struct hostent *he)
{
    int i, n;
    struct resolv_query *query = (struct resolv_query *)arg;

    if (status == ARES_EDESTRUCTION) {
        return;
    }

    if (!he || status != ARES_SUCCESS) {
        if (verbose) {
            LOGI("failed to lookup v6 address %s", ares_strerror(status));
        }
        goto CLEANUP;
    }

    if (verbose) {
        LOGI("found address name v6 address %s", he->h_name);
    }

    n = 0;
    while (he->h_addr_list[n])
        n++;

    if (n > 0) {
        struct sockaddr **new_responses = ss_realloc(query->responses,
                                                     (query->response_count + n)
                                                     * sizeof(struct sockaddr *));

        if (new_responses == NULL) {
            LOGE("failed to allocate memory for additional DNS responses");
        } else {
            query->responses = new_responses;

            for (i = 0; i < n; i++) {
                struct sockaddr_in6 *sa = ss_malloc(sizeof(struct sockaddr_in6));
                memset(sa, 0, sizeof(struct sockaddr_in6));
                sa->sin6_family = AF_INET6;
                sa->sin6_port   = query->port;
                memcpy(&sa->sin6_addr, he->h_addr_list[i], he->h_length);

                query->responses[query->response_count] = (struct sockaddr *)sa;
                if (query->responses[query->response_count] == NULL) {
                    LOGE("failed to allocate memory for DNS query result address");
                } else {
                    query->response_count++;
                }
            }
        }
    }

CLEANUP:

    query->requests[1] = 0; /* mark A query as being completed */

    /* Once all requests have completed, call client callback */
    if (all_requests_are_null(query)) {
        return process_client_callback(query);
    }
}

/*
 * Called once all requests have been completed
 */
static void
process_client_callback(struct resolv_query *query)
{
    struct sockaddr *best_address = NULL;

    if (resolv_mode == MODE_IPV4_FIRST) {
        best_address = choose_ipv4_first(query);
    } else if (resolv_mode == MODE_IPV6_FIRST) {
        best_address = choose_ipv6_first(query);
    } else {
        best_address = choose_any(query);
    }

    query->client_cb(best_address, query->data);

    for (int i = 0; i < query->response_count; i++)
        ss_free(query->responses[i]);

    ss_free(query->responses);

    if (query->free_cb != NULL)
        query->free_cb(query->data);
    else
        ss_free(query->data);

    ss_free(query);

    adjust_fd_process_timer();
}

static struct sockaddr *
choose_ipv4_first(struct resolv_query *query)
{
    for (int i = 0; i < query->response_count; i++)
        if (query->responses[i]->sa_family == AF_INET) {
            return query->responses[i];
        }

    return choose_any(query);
}

static struct sockaddr *
choose_ipv6_first(struct resolv_query *query)
{
    for (int i = 0; i < query->response_count; i++)
        if (query->responses[i]->sa_family == AF_INET6) {
            return query->responses[i];
        }

    return choose_any(query);
}

static struct sockaddr *
choose_any(struct resolv_query *query)
{
    if (query->response_count >= 1) {
        return query->responses[0];
    }

    return NULL;
}

static inline int
all_requests_are_null(struct resolv_query *query)
{
    int result = 1;

    for (int i = 0; i < sizeof(query->requests) / sizeof(query->requests[0]);
         i++)
        result = result && query->requests[i] == 0;

    return result;
}

/*
 *  DNS timeout callback
 */
static void
ares_fd_process_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    ares_process_fd(default_channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
}

/*
 * stop when idle
 * should be invoked when new socket being created or one request being finished
 */
static void
adjust_fd_process_timer()
{
    if (current_ctx_num) {
        if (!ev_is_active(&default_timer)) {
            ev_timer_set(&default_timer, 1., 1.);
            ev_timer_start(default_loop, &default_timer);
        }
    } else {
        // stop
        if (ev_is_active(&default_timer)) {
            ev_timer_stop(default_loop, &default_timer);
            ev_timer_set(&default_timer, 0., 0.);
        }
    }
}

/*
 * Handle c-ares events
 */
static void
ares_resolv_sock_state_cb(void *data, ares_socket_t s, int read, int write)
{
    struct resolv_ctx *ctx = NULL;
    find_resolv_ctx(s, &ctx);
    if (ctx == NULL) {
        LOGE("fail to find resolv ctx for %d", s);
        return;
    }

    /* stop before modifying the watcher */
    if (ev_is_active(&ctx->io)) {
        ev_io_stop(default_loop, &ctx->io);
    }

    if (read || write) {
        ev_io_set(&ctx->io, s, (read ? EV_READ : 0) | (write ? EV_WRITE : 0));
        ev_io_start(default_loop, &ctx->io);
    } else {
        // no longer being used
        ev_io_set(&ctx->io, ARES_SOCKET_BAD, 0);
        ctx->socket  = ARES_SOCKET_BAD;
        ctx->is_used = 0;
        --current_ctx_num;
    }
}

/*
 * attach newly created socket to one specific resolv_ctx
 */
static int
ares_resolv_sock_config_cb(ares_socket_t s, int type, void *data)
{
    int i;
    (void)type;  /* don't care about socket type */
    (void)data;
    // find available resolv ctx
    for (i = 0; i < MAX_RESOLVE_CTX_NUM; i++)
        if (resolv_ctxs[i].is_used == 0) {
            resolv_ctxs[i].is_used = 1;
            resolv_ctxs[i].socket  = s;
            ++current_ctx_num;
            return 0;
        }
    FATAL("no resolv ctx available");
    return 1;
}

/*
 * only enable fd process timer when we connect successfully
 */
static int
ares_resolv_sock_cb(ares_socket_t s, int type, void *data)
{
    (void)s;
    (void)type;
    (void)data;
    adjust_fd_process_timer();
    return 0;
}

static void
init_resolv_ctxs()
{
    int i;
    for (i = 0; i < MAX_RESOLVE_CTX_NUM; i++) {
        resolv_ctxs[i].is_used = 0;
        resolv_ctxs[i].socket  = ARES_SOCKET_BAD;
        ev_init(&resolv_ctxs[i].io, ares_io_handler);
    }
}

static void
cleanup_resolv_ctxs()
{
    int i;
    for (i = 0; i < MAX_RESOLVE_CTX_NUM; i++)
        if (ev_is_active(&resolv_ctxs[i].io)) {
            ev_io_stop(default_loop, &resolv_ctxs[i].io);
        }
}

/*
 * find resolv_ctx based on socket fd
 */
static void
find_resolv_ctx(ares_socket_t s, struct resolv_ctx **ctx)
{
    int i;
    for (i = 0; i < MAX_RESOLVE_CTX_NUM; i++)
        if (resolv_ctxs[i].is_used == 1 &&
            resolv_ctxs[i].socket == s) {
            *ctx = &resolv_ctxs[i];
            return;
        }
    *ctx = NULL;
    return;
}
