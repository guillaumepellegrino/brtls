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
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <netinet/ether.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include "brtls.h"
#include "tls.h"

typedef struct _brtls_ctx brtls_ctx_t;
struct _brtls_ctx {
    const char *ifname;
    int rawfd;
    tls_t *tls;
    tls_cfg_t tls_cfg;
    bool server;
    int vlanid; /** VLAN ID set on packets sent over TLS */
};

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

static bool runcmd(const char *argv[]) {
    int pid = fork();

    if (pid == 0) {
        execvp(argv[0], (char **) argv);
        log("Failed to run command %s: %m", argv[0]);
        exit(1);
    }
    else if (pid > 0) {
        waitpid(pid, NULL, 0);
        return true;
    }
    else {
        log("Failed to fork(): %m");
        return false;
    }
}

/**
 * Run ethtool command
 */
static bool ethtool_set(const char *ifname, const char *option, const char *value) {
    const char *argv[] = {"ethtool", "-K", ifname, option, value, NULL};

    if (!runcmd(argv)) {
        log("ethtool -K %s %s %s -> failed", ifname, option, value);
        log("Did you install ethtool ?");
    }

    return true;
}

/**
 * Disable HW TCP Reassembly using ethtool
 *
 * ethtool -K eno1 tso off
 * ethtool -K eno1 ufo off
 * ethtool -K eno1 gso off
 * ethtool -K eno1 gro off
 *
 */
static bool ethtool_disable_tcp_reassembly(const char *ifname) {
    bool ret = true;

    ret &= ethtool_set(ifname, "tso", "off");
    ret &= ethtool_set(ifname, "ufo", "off");
    ret &= ethtool_set(ifname, "gso", "off");
    ret &= ethtool_set(ifname, "gro", "off");

    return ret;
}

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
ssize_t forward_intf2tls(int rawfd, tls_t *tls, int vlanid) {
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
    if (vlanid != -1) {
        vlantci = vlanid;
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
 * Verify if daemon is alive
 */
static bool daemon_is_running(const char *pidfile) {
    bool running = false;
    int pid = 0;
    FILE *fp = fopen(pidfile, "r");

    if (fp) {
        fscanf(fp, "%d", &pid);
        if (pid) {
            running = (kill(pid, 0) == 0);
        }
        fclose(fp);
    }

    return running;
}

/**
 * Write daemon pid to pidfile
 */
static bool daemon_write_pidfile(const char *pidfile) {
    FILE *fp = fopen(pidfile, "w");
    if (!fp) {
        return false;
    }
    fprintf(fp, "%d\n", getpid());
    fclose(fp);
    return true;
}

/**
 * Event loop:
 * 1. Forward packets from interface to tls socket
 * 2. Forward packets from tls socket to interface
 */
static int brtls_eventloop(brtls_ctx_t *ctx) {
    int rt = 1;
    struct pollfd pollfds[2] = {
        {
            .fd = ctx->rawfd,
            .events = POLLIN,
        },
        {
            .fd = tls_socket(ctx->tls),
            .events = POLLIN,
        },
    };

    debug("TLS Bridge: Entering event loop");

    while (poll(pollfds, sizeof(pollfds)/sizeof(*pollfds), -1) > 0) {
        if (pollfds[0].revents & POLLIN) {
            ssize_t size = forward_intf2tls(ctx->rawfd, ctx->tls, ctx->vlanid);
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
        if (pollfds[0].revents & (POLLERR|POLLHUP|POLLNVAL)) {
            log("raw socket returned an error: Exit program");
            rt = 0;
            break;
        }
        if (pollfds[1].revents & POLLIN) {
            ssize_t size = forward_tls2intf(ctx->tls, ctx->rawfd);
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
        if (pollfds[1].revents & (POLLERR|POLLHUP|POLLNVAL)) {
            log("tls socket returned an error");
            break;
        }
    }

    debug("TLS Bridge: Exiting event loop");
    return rt;
}

/**
 * Display help
 */
static void help() {
    debug("Usage: brtls [OPTION] ipaddress port");
    debug("Bridge two network interfaces over TLS.");
    debug("");
    debug("Options:");
    debug("  -i, --ifname=NAME              Interface name (mandatory argument)");
    debug("  -c, --cert=FILE                Public certificate (default: cert.pem)");
    debug("  -k, --key=FILE                 Private key (default: key.pem)");
    debug("  -v, --vlanid=[-1, 255]         Set VLANID on packets sent over TLS (default: -1)");
    debug("                                 vlandid=-1 left the vlan header unchanged");
    debug("                                 vlanid=0 remove the vlan header");
    debug("  -p, --pid=FILE                 Write the daemon pid in this file (default: /var/run/brtls.pid)");
    debug("  -d, --daemon                   Daemonize the program after startup");
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
    brtls_ctx_t _ctx = {
        .ifname = NULL,
        .rawfd = -1,
        .tls = NULL,
        .tls_cfg = {0},
        .server = false,
        .vlanid = -1,
    };
    brtls_ctx_t *ctx = &_ctx;
    int opt = -1;
    int rt = 1;
    bool daemonize = false;
    const char *pidfile = "/var/run/brtls.pid";
    const char *short_options = "i:c:k:v:p:dshV";
    const struct option long_options[] = {
        {"ifname",      required_argument,  0, 'i'},
        {"cert",        required_argument,  0, 'c'},
        {"key",         required_argument,  0, 'k'},
        {"vlanid",      required_argument,  0, 'v'},
        {"pid-file",    required_argument,  0, 'p'},
        {"daemon",      no_argument,        0, 'd'},
        {"server",      no_argument,        0, 's'},
        {"help",        no_argument,        0, 'h'},
        {"version",     no_argument,        0, 'V'},
        {0}
    };

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                ctx->ifname = optarg;
                break;
            case 'c':
                ctx->tls_cfg.certificate = optarg;
                break;
            case 'k':
                ctx->tls_cfg.privatekey = optarg;
                break;
            case 'v':
                ctx->vlanid = atoi(optarg);
                break;
            case 'p':
                pidfile = optarg;
                break;
            case 'd':
                daemonize = true;
                break;
            case 's':
                ctx->server = true;
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

    ctx->tls_cfg.address = argc > optind+0 ? argv[optind+0] : "0.0.0.0";
    ctx->tls_cfg.port    = argc > optind+1 ? argv[optind+1] : "9000";

    if (!ctx->ifname) {
        log("ifname argument was not provided");
        goto exit;
    }

    if (geteuid() != 0) {
        log("Please start the program with root permissions");
        goto exit;
    }

    if (daemonize && daemon_is_running(pidfile)) {
        log("daemon is already running");
        goto exit;
    }

    if (!ethtool_disable_tcp_reassembly(ctx->ifname)) {
        log("ethtool errors are ignored");
    }

    if ((ctx->rawfd = raw_open_socket(ctx->ifname)) < 0) {
        log("Failed to open raw socket on interface %s", ctx->ifname);
        goto exit;
    }

    if (!(ctx->tls = tls_create())) {
        log("Failed to create tls socket");
        goto exit;
    }

    if (ctx->server) {
        if (tls_listen(ctx->tls, &ctx->tls_cfg) != 0) {
            log("Failed to listen on tls socket");
            goto exit;
        }
    }
    else {
        log("Connecting");
        if (tls_connect(ctx->tls, &ctx->tls_cfg) != 0) {
            log("Failed to connect");
            goto exit;
        }
        log("Connected");
    }

    debug("TLS Bridge: Initialized");

    if (daemonize) {
        debug("Daemonize");
        if (daemon(0, 0) != 0) {
            log("Failed to daemonize: %m");
            goto exit;
        }
        daemon_write_pidfile(pidfile);
    }


    if (ctx->server) {
        while (true) {
            log("Waiting for client to connect");
            while (tls_accept_first_client(ctx->tls) != 0) {
                if (errno == EINTR) {
                    goto exit;
                }
                log("Failed to accept tls client");
                sleep(1);
                continue;
            }
            log("Client connected");

            if (brtls_eventloop(ctx) == 0) {
                break;
            }
        }
    }
    else {
        while (true) {
            int retry = 1;
            if (brtls_eventloop(ctx) == 0) {
                break;
            }

            log("Retrying to connect to server");
            while (tls_connect(ctx->tls, &ctx->tls_cfg) != 0) {
                if (errno == EINTR) {
                    goto exit;
                }
                log("Failed to connect to server: Retry in %d seconds.", retry);
                sleep(retry);
                retry *= 2;
                if (retry > 60) {
                    retry = 60;
                }
                log("Retrying to connect to server");
            }
            log("Connected to server");
        }
    }

exit:
    debug("TLS Bridge cleanup");

    if (ctx->rawfd >= 0) {
        close(ctx->rawfd);
    }
    if (ctx->tls) {
        tls_destroy(ctx->tls);
    }

    return rt;
}
