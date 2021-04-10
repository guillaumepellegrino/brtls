#pragma once

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

typedef struct _tls tls_t;
typedef struct _tls_cfg tls_cfg_t;

union sockaddr_u {
    struct sockaddr generic;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
};

struct _tls_cfg {
    const char *certificate; // path to certificate file
    const char *privatekey;  // path to private key file
    const char *address;
    const char *port;
    union sockaddr_u sockaddr;
};

extern bool tls_accept_expired_cert;

tls_t *tls_create();
void tls_destroy(tls_t *tls);
int tls_listen(tls_t *tls, const tls_cfg_t *cfg);
int tls_accept_first_client(tls_t *tls);
int tls_connect(tls_t *tls, const tls_cfg_t *cfg);
int tls_socket(tls_t *tls);
ssize_t tls_read(tls_t *tls, void *buf, size_t count);
ssize_t tls_write(tls_t *tls, void *buf, size_t count);
