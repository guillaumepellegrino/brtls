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

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <netinet/ether.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include "brtls.h"
#include "tls.h"

/**
 * global buffer, used for reading and writting
 */
static union __attribute__((packed)) {
    uint8_t buff[8096];
    struct __attribute__((packed)) {
        struct __attribute__((packed)) ethhdr eth;
        uint8_t data[];
    } ethpkt;
    struct __attribute__((packed)) {
        struct __attribute__((packed)) ethhdr eth;
        uint16_t vlantci;
        uint16_t vlanproto;
        uint8_t data[];
    } ethvlanpkt;
} g_packet;

/**
 * VLAN ID set on packets sent over TLS
 */
static int g_vlanid = -1;

/**
 * Open a raw socket and bind it to ifname
 */
static int raw_open_socket(const char *ifname) {
    int ifindex = -1;
    int s = -1;
    int yes = 1;

    //Get interface index
    if ((ifindex = if_nametoindex(ifname)) <= 0) {
        log("Failed to get %s ifindex: %m", ifname);
        goto error;
    }

    //Create raw socket
    if ((s = socket(AF_PACKET, SOCK_RAW, 0)) < 0) {
        log("Failed to create raw socket: %m");
        goto error;
    }

    //Ask for Auxiliary data
    if (setsockopt(s, SOL_PACKET, PACKET_AUXDATA, &yes, sizeof(yes)) != 0) {
        log("Failed to set sockopt PACKET_AUXDATA: %m");
        goto error;
    }

    //Bind interface
    struct sockaddr_ll saddr = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_pkttype = PACKET_OTHERHOST,
        .sll_ifindex  = ifindex,
    };
    socklen_t saddrlen = sizeof(saddr);
    if (bind(s, (struct sockaddr*)&saddr, saddrlen) != 0) {
        log("Failed to bind raw socket interface: %m");
        goto error;
    }

    //Enter promiscouous mode
    struct packet_mreq mreq = {
        .mr_ifindex = ifindex,
        .mr_type = PACKET_MR_PROMISC,
    };
    if (setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0) {
        log("Failed to enter promiscouous mode: %m");
        goto error;
    }

    return s;
error:
    if (s >= 0) {
        close(s);
    }
    return -1;
}

/**
 * Read a packet from TLS socket and forward it to Raw socket
 */
ssize_t forward_tls2intf(tls_t *tls, int rawfd) {
    ssize_t rdsize = 0, wrsize = 0;

    if ((rdsize = tls_read(tls, &g_packet, sizeof(g_packet))) <= 0) {
        if (rdsize < 0) {
            log("tls_read() failed: %m");
        }
        return rdsize;
    }

    wrsize = write(rawfd, &g_packet, rdsize);
    if (wrsize < 0) {
        log("write(rawfd, &g_packet), %zd) failed: %m", rdsize);
    }

    return wrsize;
}

/**
 * Read a packet from Raw socket and forward it to TLS socket
 */
ssize_t forward_intf2tls(int rawfd, tls_t *tls) {
    static char controldata[1000];
    struct iovec vec;
    ssize_t rdsize = 0, wrsize = 0;
    uint16_t vlantci = 0;

    vec.iov_base = &g_packet;
    vec.iov_len = sizeof(g_packet)-4;

    struct msghdr hdr = {0};
    hdr.msg_iov = &vec;
    hdr.msg_iovlen = 1;
    hdr.msg_control = controldata;
    hdr.msg_controllen = sizeof(controldata);

    /* read response */
    if ((rdsize = recvmsg(rawfd, &hdr, 0)) < 0) {
        log("Failed to recvmsg: %m");
        return -1;
    }

    if (rdsize > (ssize_t)vec.iov_len) {
        log("received jumbo frame of %zd bytes len, truncated", rdsize);
        rdsize = vec.iov_len;
    }

    /* retrieve vlan id */
    struct cmsghdr *cmsgptr = NULL;
    for (cmsgptr = CMSG_FIRSTHDR(&hdr); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&hdr, cmsgptr)) {
        if (cmsgptr->cmsg_type == PACKET_AUXDATA) {
            struct tpacket_auxdata *aux = (struct tpacket_auxdata *)CMSG_DATA(cmsgptr);
            vlantci = aux->tp_vlan_tci;
            break;
        }
    }

    /** force vlanid if specified */
    if (g_vlanid != -1) {
        vlantci = g_vlanid;
    }

    /* insert vlan header */
    if (vlantci) {
        uint16_t ethproto = g_packet.ethpkt.eth.h_proto;
        memmove(g_packet.ethvlanpkt.data, g_packet.ethpkt.data, rdsize-sizeof(g_packet.ethpkt));
        g_packet.ethvlanpkt.eth.h_proto = htons(ETH_P_8021Q);
        g_packet.ethvlanpkt.vlantci = htons(vlantci);
        g_packet.ethvlanpkt.vlanproto = ethproto;
        rdsize += 4;
    }

    wrsize = tls_write(tls, &g_packet, rdsize);

    if (wrsize < 0) {
        log("tls_write(tls, &g_packet, %zd) failed: %m", rdsize);
    }

    return wrsize;
}

/**
 * Display help
 */
static void help() {
    debug("Usage: brtls [OPTION] ipaddress port");
    debug("Bridge two interfaces over TLS.");
    debug("");
    debug("Options:");
    debug("  -i, --ifname=NAME              interface name (mandatory argument)");
    debug("  -c, --cert=FILE                public certificate");
    debug("  -k, --key=FILE                 private key");
    debug("  -v, --vlanid=[-1, 255]         Set VLANID on packets sent over TLS.");
    debug("                                 vlandid=-1 left the vlan header unchanged (default).");
    debug("                                 vlanid=0 remove the vlan header.");
    debug("  -s, --server                   Run in server mode");
    debug("  -h, --help                     Display this help");
    debug("  -V, --version                  Display the version");
    debug("");
}

/**
 * Display version
 */
static void version() {
    debug("brtls 1.0");
}

int main(int argc, char *argv[]) {
    const char *ifname = NULL;
    int epoll = -1;
    int sigfd = -1;
    int rawfd = -1;
    int tlsfd = -1;
    int opt = -1;
    int rt = 1;
    sigset_t sigmask = {0};
    tls_t *tls = NULL;
    tls_cfg_t tls_cfg = {0};
    bool server = false;
    bool daemonize = false;
    struct epoll_event epoll_event = {0};
    const char *short_options = "i:c:k:v:sdhV";
    const struct option long_options[] = {
        {"ifname",      required_argument,  0, 'i'},
        {"cert",        required_argument,  0, 'c'},
        {"key",         required_argument,  0, 'k'},
        {"vlanid",      required_argument,  0, 'v'},
        {"server",      no_argument,        0, 's'},
        {"daemon",      no_argument,        0, 'd'},
        {"help",        no_argument,        0, 'h'},
        {"version",     no_argument,        0, 'V'},
        {0}
    };

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                ifname = optarg;
                break;
            case 'c':
                tls_cfg.certificate = optarg;
                break;
            case 'k':
                tls_cfg.privatekey = optarg;
                break;
            case 'v':
                g_vlanid = atoi(optarg);
                break;
            case 's':
                server = true;
                break;
            case 'd':
                daemonize = true;
                break;
            case 'h':
                help();
                return 0;
            case 'V':
                version();
                return 0;
            default:
                help();
                return 1;
        }
    }

    tls_cfg.address = argc > optind+0 ? argv[optind+0] : "0.0.0.0";
    tls_cfg.port    = argc > optind+1 ? argv[optind+1] : "9000";

    if ((epoll = epoll_create1(EPOLL_CLOEXEC)) < 0) {
        log("Failed to create epoll: %m");
        goto exit;
    }

    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGTERM);
    sigaddset(&sigmask, SIGQUIT);
    if (sigprocmask(SIG_BLOCK, &sigmask, NULL) != 0) {
        log("Failed to block sigmask: %m");
        goto exit;
    }

    if ((sigfd = signalfd(-1, &sigmask, SFD_NONBLOCK|SFD_CLOEXEC)) < 0) {
        log("Failed to signal fd: %m");
        goto exit;
    }

    if (ifname && (rawfd = raw_open_socket(ifname)) < 0) {
        log("Failed to open raw socket on interface %s", ifname);
        goto exit;
    }

    if (!(tls = tls_create())) {
        log("Failed to create tls socket");
        goto exit;
    }

    if (server) {
        if (tls_listen(tls, &tls_cfg) != 0) {
            log("Failed to listen on tls socket");
            goto exit;
        }

        log("Waiting for client to connect");
        if (tls_accept_first_client(tls, sigfd) != 0) {
            log("Failed to accept on tls client");
            goto exit;
        }
    }
    else {
        if (tls_connect(tls, &tls_cfg, sigfd) != 0) {
            log("Failed to connect");
            goto exit;
        }
    }

    if (rawfd == -1) {
        log("TLS client connected");
        goto exit;
    }

    tlsfd = tls_socket(tls);

    epoll_event.events = EPOLLIN;
    epoll_event.data.fd = rawfd;
    if (epoll_ctl(epoll, EPOLL_CTL_ADD, rawfd, &epoll_event) != 0) {
        log("Failed to add raw %s socket to epoll: %m", ifname);
        goto exit;
    }

    epoll_event.events = EPOLLIN;
    epoll_event.data.fd = tlsfd;
    if (epoll_ctl(epoll, EPOLL_CTL_ADD, tlsfd, &epoll_event) != 0) {
        log("Failed to add raw %s socket to epoll: %m", ifname);
        goto exit;
    }

    epoll_event.events = EPOLLIN;
    epoll_event.data.fd = sigfd;
    if (epoll_ctl(epoll, EPOLL_CTL_ADD, sigfd, &epoll_event) != 0) {
        log("Failed to add raw %s socket to epoll: %m", ifname);
        goto exit;
    }

    debug("TLS Bridge initialized");

    if (daemonize) {
        debug("Daemonize");
        if (daemon(0, 0) != 0) {
            log("Failed to daemonize: %m");
            goto exit;
        }
    }

    while (epoll_wait(epoll, &epoll_event, 1, -1) > 0) {
        if (epoll_event.data.fd == rawfd) {
            ssize_t size = forward_intf2tls(rawfd, tls);
            if (size < 0) {
                if (errno != EAGAIN) {
                    log("forward_intf2tls failed: %m");
                }
            }
            else if (size == 0) {
                log("socket closed");
                break;
            }
        }
        else if (epoll_event.data.fd == tlsfd) {
            ssize_t size = forward_tls2intf(tls, rawfd);
            if (size < 0) {
                if (errno != EAGAIN) {
                    log("forward_tls2intf failed: %m");
                }
            }
            else if (size == 0) {
                log("socket closed");
                break;
            }
        }
        else if (epoll_event.data.fd == sigfd) {
            debug("\nSignal received: Exit program");
            rt = 0;
            break;
        }
    }

    debug("TLS Bridge cleanup");

exit:
    if (rawfd >= 0) {
        close(rawfd);
    }
    if (tls) {
        tls_destroy(tls);
    }
    if (sigfd >= 0) {
        close(sigfd);
    }
    if (epoll >= 0) {
        close(epoll);
    }

    return rt;
}
