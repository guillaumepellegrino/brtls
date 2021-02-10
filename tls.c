/*
 * Copyright (C) 2020 Guillaume Pellegrino
 * This file is part of brtls <https://github.com/guillaumepellegrino/brtls>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GUN_SOURCE
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "brtls.h"
#include "tls.h"

struct _tls {
    SSL_CTX *ctx;
    SSL *ssl;
    int server;
    int socket;
};

static int tls_socket_refcount = 0;

/**
 * Initialize openssl
 */
static void tls_initialize() {
    if (tls_socket_refcount == 0) {
        ERR_load_BIO_strings();
        ERR_load_CRYPTO_strings();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        SSL_library_init();
    }

    tls_socket_refcount++;
}

/**
 * Cleanip openssl
 */
static void tls_cleanup() {
    tls_socket_refcount--;

    if (tls_socket_refcount == 0) {
        EVP_cleanup();
    }
}

/**
 * Poll socket
 */
static int pollsocket(int socket, int sockevents) {
    struct pollfd pollfds[1] = {
        {
            .fd = socket,
            .events = sockevents,
        },
    };

    do {
        if (poll(pollfds, sizeof(pollfds)/sizeof(*pollfds), -1) < 0) {
            log("poll error: %m");
            return -1;
        }
        if (pollfds[0].revents & (POLLERR|POLLHUP|POLLNVAL)) {
            log("socket returned an error");
            errno = EIO;
            return -1;
        }
    } while (!(pollfds[0].revents & sockevents));

    return 0;
}

/**
 * Create a TLS socket
 */
tls_t *tls_create() {
    tls_t *tls = NULL;
    const SSL_METHOD *method = NULL;

    tls_initialize();

    if (!(tls = calloc(1, sizeof(tls_t)))) {
        log("calloc(tls_t) failed: %m");
        goto error;
    }
    tls->server = -1;
    tls->socket = -1;

    if (!(method = SSLv23_method())) {
        log("Unknow SSL method");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if (!(tls->ctx = SSL_CTX_new(method))) {
        log("Failed to create SSL context");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    return tls;

error:
    tls_destroy(tls);
    return NULL;
}

/**
 * Destroy TLS socket
 */
void tls_destroy(tls_t *tls) {
    if (tls) {
        if (tls->ssl) {
            SSL_free(tls->ssl);
        }
        if (tls->ctx) {
            SSL_CTX_free(tls->ctx);
        }
        if (tls->socket >= 0) {
            close(tls->socket);
        }
        if (tls->server >= 0) {
            close(tls->server);
        }
        free(tls);
    }
    tls_cleanup();
}

/**
 * Create a TCP listen socket using getaddrinfo() acording cfg->addr and cfg->port
 */
static int tcp_listen_socket(const tls_cfg_t *cfg) {
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *ai_list = NULL, *ai = NULL;
    int rt = -1;
    int yes = 1;
    int server = -1;

    if ((rt = getaddrinfo(cfg->address, cfg->port, &hints, &ai_list)) != 0) {
        log("Failed to resolve %s:%s. %s", cfg->address, cfg->port, gai_strerror(rt));
        return -1;
    }

    for (ai = ai_list; ai; ai = ai->ai_next) {
        if ((server = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
            log("Failed to create TCP server socket: %m");
            continue;
        }

        if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
            log("Failed to set setsockopt(SO_REUSEADDR): %m");
            close(server), server = -1;
            continue;
        }

        if (bind(server, ai->ai_addr, ai->ai_addrlen) == -1) {
            log("Failed to bind socket: %m");
            close(server), server = -1;
            continue;
        }

        if (listen(server, 1) < 0) {
            log("Failed to listen on socket: %m");
            close(server), server = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(ai_list);

    return server;
}

/**
 * Create a TLS listen socket according configuration.
 * The socket use two-way TLS authentication.
 */
int tls_listen(tls_t *tls, const tls_cfg_t *cfg) {
    const char *cert = NULL;
    const char *key = NULL;

    if (!tls || !cfg) {
        log("NULL argument");
        goto error;
    }

    cert = (cfg->certificate?cfg->certificate:"cert.pem");
    key = (cfg->privatekey?cfg->privatekey:"key.pem");

    if (SSL_CTX_load_verify_locations(tls->ctx, cert, NULL) != 1) {
        log("Could not set the CA file location");
        goto error;
    }

    SSL_CTX_set_client_CA_list(tls->ctx, SSL_load_client_CA_file(cert));

    if (SSL_CTX_use_certificate_file(tls->ctx, cert, SSL_FILETYPE_PEM) != 1) {
        log("Failed to open certificate");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if (SSL_CTX_use_PrivateKey_file(tls->ctx, key, SSL_FILETYPE_PEM) != 1 ) {
        log("Failed to open private key");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if (SSL_CTX_check_private_key(tls->ctx) != 1) {
        log("Server's certificate and key don't match");
        goto error;
    }

    SSL_CTX_set_mode(tls->ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(tls->ctx, 1);

    if ((tls->server = tcp_listen_socket(cfg)) < 0) {
        log("Failed to create TCP listen socket");
        goto error;
    }

    return 0;

error:
    return -1;
}

/**
 * The TLS listen socket accept the first TLS client connecting.
 */
int tls_accept_first_client(tls_t *tls) {
    if (!tls || !tls->ctx) {
        log("NULL argument");
        goto error;
    }

    if (tls->ssl) {
        SSL_free(tls->ssl);
        tls->ssl = NULL;
    }
    if (tls->socket >= 0) {
        close(tls->socket);
        tls->socket = -1;
    }

    if (pollsocket(tls->server, POLLIN) != 0) {
        goto error;
    }

    if ((tls->socket = accept(tls->server, NULL, NULL)) < 0) {
        log("Failed to accept socket: %m");
        goto error;
    }

    if (!(tls->ssl = SSL_new(tls->ctx))) {
        log("Failed to create SSL socket");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    SSL_set_fd(tls->ssl, tls->socket);

    int rt = -1;
    while ((rt = SSL_accept(tls->ssl)) < 0) {
        switch (SSL_get_error(tls->ssl, rt)) {
            case SSL_ERROR_WANT_READ:
                if (pollsocket(tls->socket, POLLIN) != 0) {
                    goto error;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                if (pollsocket(tls->socket, POLLOUT) != 0) {
                    goto error;
                }
                break;
            default:
                log("SSL accept failed");
                ERR_print_errors_fp(stderr);
                goto error;
        }
    }

    return 0;

error:
    return -1;
}

/**
 * Create a TLS socket according configuration and connect to server.
 * The socket use two-way TLS authentication.
 */
int tls_connect(tls_t *tls, const tls_cfg_t *cfg) {
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *ai_list = NULL, *ai = NULL;
    int rt = -1;
    const char *cert = NULL;
    const char *key = NULL;

    if (!tls || !cfg) {
        log("NULL argument");
        goto error;
    }

    if (tls->ssl) {
        SSL_free(tls->ssl);
        tls->ssl = NULL;
    }
    if (tls->socket >= 0) {
        close(tls->socket);
        tls->socket = -1;
    }

    cert = (cfg->certificate?cfg->certificate:"cert.pem");
    key = (cfg->privatekey?cfg->privatekey:"key.pem");

    if (SSL_CTX_load_verify_locations(tls->ctx, cert, NULL) != 1) {
        log("Could not set the CA file location");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if (SSL_CTX_use_certificate_file(tls->ctx, cert, SSL_FILETYPE_PEM) != 1) {
        log("Failed to open certificate");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if (SSL_CTX_use_PrivateKey_file(tls->ctx, key, SSL_FILETYPE_PEM) != 1 ) {
        log("Failed to open private key");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if (SSL_CTX_check_private_key(tls->ctx) != 1) {
        log("Server's certificate and key don't match");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    SSL_CTX_set_mode(tls->ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(tls->ctx, 1);

    if ((rt = getaddrinfo(cfg->address, cfg->port, &hints, &ai_list)) != 0) {
        log("Failed to resolve %s:%s. %s", cfg->address, cfg->port, gai_strerror(rt));
        goto error;
    }

    for (ai = ai_list; ai; ai = ai->ai_next) {
        if ((tls->socket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
            log("Failed to create TCP client socket: %m");
            continue;
        }

        if (connect(tls->socket, ai->ai_addr, ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
            log("Failed to connect: %m");
            close(tls->socket), tls->socket = -1;
            continue;
        }

        if (pollsocket(tls->socket, POLLOUT) != 0) {
            close(tls->socket), tls->socket = -1;
            if (errno != EINTR) {
                continue;
            }
            else {
                goto error;
            }
        }
    }

    if (!(tls->ssl = SSL_new(tls->ctx))) {
        log("Failed to create SSL socket");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    SSL_set_fd(tls->ssl, tls->socket);

    while ((rt = SSL_connect(tls->ssl)) < 0) {
        switch (SSL_get_error(tls->ssl, rt)) {
            case SSL_ERROR_WANT_READ:
                if (pollsocket(tls->socket, POLLIN) != 0) {
                    goto error;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                if (pollsocket(tls->socket, POLLOUT) != 0) {
                    goto error;
                }
                break;
            default:
                log("SSL connection failed");
                ERR_print_errors_fp(stderr);
                goto error;
        }
    }
    if (ai_list) {
        freeaddrinfo(ai_list);
    }
    return 0;

error:
    if (ai_list) {
        freeaddrinfo(ai_list);
    }
    if (tls->socket >= 0) {
        close(tls->socket), tls->socket = -1;
    }
    return -1;
}

/**
 * Return the TLS socket file description
 */
int tls_socket(tls_t *tls) {
    return tls ? tls->socket : -1;
}

/**
 * TLS read buf
 */
ssize_t tls_read(tls_t *tls, void *buf, size_t count) {
    return (tls && tls->ssl) ? SSL_read(tls->ssl, buf, count) : -1;
}

/**
 * TLS write buf
 */
ssize_t tls_write(tls_t *tls, void *buf, size_t count) {
    return (tls && tls->ssl) ? SSL_write(tls->ssl, buf, count) : -1;
}

