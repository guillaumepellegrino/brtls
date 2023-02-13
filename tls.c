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
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "brtls.h"
#include "tls.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define TLS_method SSLv23_method
#endif

#ifndef CIPHER_LIST
#define CIPHER_LIST "EDH+CAMELLIA:EDH+aRSA:EECDH+aRSA+AESGCM:EECDH+aRSA+SHA384:EECDH+aRSA+SHA256:EECDH:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:AES128-SHA:+CAMELLIA256:+AES256:+CAMELLIA128:+AES128:+kRSA:+SSLv3:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!RC4:!SEED:-DSS:DHE-DSS-AES256-GCM-SHA384"
#endif

struct _tls {
    SSL_CTX *ctx;
    SSL *ssl;
    int server;
    int socket;
};

static const char *default_certs[] = {
    "/etc/brtls-cert.pem",
    "/etc/brtls/cert.pem",
    "brtls-cert.pem",
    "cert.pem",
    NULL,
};
static const char *default_keys[] = {
    "/etc/brtls-key.pem",
    "/etc/brtls/key.pem",
    "brtls-key.pem",
    "key.pem",
    NULL,
};

bool tls_accept_expired_cert = false;

static int tls_socket_refcount = 0;

int setnonblocking(int fd, int nonblocking) {
    int flags, newflags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl(F_GETFL)");
        return -1;
    }
    if (nonblocking)
        newflags = flags | (int) O_NONBLOCK;
    else
        newflags = flags & ~((int) O_NONBLOCK);
    if (newflags != flags)
        if (fcntl(fd, F_SETFL, newflags) < 0) {
            perror("fcntl(F_SETFL)");
            return -1;
        }
    return 0;
}

/**
 * Log ssl error to syslog
 */
static int log_ssl_error(const char *str, size_t len, void *u) {
    (void) len;
    (void) u;

    syslog(LOG_INFO, "%s", str);

    return 0;
}

/**
 * Return the first existing file from NULL terminated list
 */
const char *openfile(const char *files[]) {
    struct stat st = {0};

    int i;
    for (i = 0; files[i]; i++) {
        if (stat(files[i], &st) == 0) {
            log("%s found", files[i]);
            return files[i];
        }
        log("%s: %m", files[i]);
    }

    return NULL;
}


static int tls_verify_cert_callback(int ok, X509_STORE_CTX *store) {
    char data[256];
    int err = X509_STORE_CTX_get_error(store);
    X509 *cert = X509_STORE_CTX_get_current_cert(store);

    if (ok) {
        log("Certificate is ok");
        return ok;
    }

    switch (err) {
        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_CERT_HAS_EXPIRED:
            if (tls_accept_expired_cert) {
                log("Acepting expired certificate");
                return 1;
            }
            break;
        default:
            break;
    }

    log("Failed to verify certificate");
    log("   Depth: %d", X509_STORE_CTX_get_error_depth(store));
    X509_NAME_oneline(X509_get_issuer_name(cert), data, sizeof(data));
    log("   Issuer: %s",data);
    X509_NAME_oneline(X509_get_subject_name(cert), data, sizeof(data));
    log("   Subject: %s", data);
    log("   Error %d: %s", err, X509_verify_cert_error_string(err));

    return ok;
}

/**
 * Initialize openssl
 */
static void tls_initialize() {
    if (tls_socket_refcount == 0) {
        ERR_load_BIO_strings();
        ERR_load_CRYPTO_strings();
        SSL_load_error_strings();
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

    if (!(method = TLS_method())) {
        log("Unknow SSL method");
        ERR_print_errors_cb(log_ssl_error, NULL);
        goto error;
    }

    if (!(tls->ctx = SSL_CTX_new(method))) {
        log("Failed to create SSL context");
        ERR_print_errors_cb(log_ssl_error, NULL);
        goto error;
    }

    if (SSL_CTX_set_cipher_list(tls->ctx, CIPHER_LIST) != 1) {
        log("Failed to set cipher list");
        ERR_print_errors_cb(log_ssl_error, NULL);
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

    if (!(cert = cfg->certificate)) {
        if (!(cert = openfile(default_certs))) {
            log("Certificate file not found");
            goto error;
        }
    }
    if (!(key = cfg->privatekey)) {
        if (!(key = openfile(default_keys))) {
            log("Private key file not found");
            goto error;
        }
    }

    if (SSL_CTX_load_verify_locations(tls->ctx, cert, NULL) != 1) {
        log("Could not set the CA file location");
        ERR_print_errors_cb(log_ssl_error, NULL);
        goto error;
    }

    SSL_CTX_set_client_CA_list(tls->ctx, SSL_load_client_CA_file(cert));

    if (SSL_CTX_use_certificate_file(tls->ctx, cert, SSL_FILETYPE_PEM) != 1) {
        log("Failed to open certificate");
        ERR_print_errors_cb(log_ssl_error, NULL);
        goto error;
    }

    if (SSL_CTX_use_PrivateKey_file(tls->ctx, key, SSL_FILETYPE_PEM) != 1 ) {
        log("Failed to open private key");
        ERR_print_errors_cb(log_ssl_error, NULL);
        goto error;
    }

    if (SSL_CTX_check_private_key(tls->ctx) != 1) {
        log("Server's certificate and key don't match");
        goto error;
    }

    SSL_CTX_set_mode(tls->ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, tls_verify_cert_callback);
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

    if ((tls->socket = accept(tls->server, NULL, NULL)) < 0) {
        log("Failed to accept socket: %m");
        goto error;
    }

    if (!(tls->ssl = SSL_new(tls->ctx))) {
        log("Failed to create SSL socket");
        ERR_print_errors_cb(log_ssl_error, NULL);
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
                ERR_print_errors_cb(log_ssl_error, NULL);
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

    if (!(cert = cfg->certificate)) {
        if (!(cert = openfile(default_certs))) {
            log("Certificate file not found");
            goto error;
        }
    }
    if (!(key = cfg->privatekey)) {
        if (!(key = openfile(default_keys))) {
            log("Private key file not found");
            goto error;
        }
    }

    if (SSL_CTX_load_verify_locations(tls->ctx, cert, NULL) != 1) {
        log("Could not set the CA file location");
        ERR_print_errors_cb(log_ssl_error, NULL);
        goto error;
    }

    if (SSL_CTX_use_certificate_file(tls->ctx, cert, SSL_FILETYPE_PEM) != 1) {
        log("Failed to open certificate");
        ERR_print_errors_cb(log_ssl_error, NULL);
        goto error;
    }

    if (SSL_CTX_use_PrivateKey_file(tls->ctx, key, SSL_FILETYPE_PEM) != 1 ) {
        log("Failed to open private key");
        ERR_print_errors_cb(log_ssl_error, NULL);
        goto error;
    }

    if (SSL_CTX_check_private_key(tls->ctx) != 1) {
        log("Server's certificate and key don't match");
        ERR_print_errors_cb(log_ssl_error, NULL);
        goto error;
    }

    SSL_CTX_set_mode(tls->ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, tls_verify_cert_callback);
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

        setnonblocking(tls->socket, 1);

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
        ERR_print_errors_cb(log_ssl_error, NULL);
        goto error;
    }

    SSL_set_fd(tls->ssl, tls->socket);

    while ((rt = SSL_connect(tls->ssl)) < 0) {
        switch (SSL_get_error(tls->ssl, rt)) {
            case SSL_ERROR_WANT_READ:
                log("SSL_ERROR_WANT_READ");
                exit(1);
                if (pollsocket(tls->socket, POLLIN) != 0) {
                    goto error;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                log("SSL_ERROR_WANT_WRITE");
                exit(1);
                if (pollsocket(tls->socket, POLLOUT) != 0) {
                    goto error;
                }
                break;
            default:
                log("SSL connection failed");
                ERR_print_errors_cb(log_ssl_error, NULL);
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

