# Installation
```
cd brtls
make
sudo make install
```

# Usage
```
Usage: brtls [OPTION] ipaddress port
Bridge two network interfaces over TLS.

Options:
  -i, --ifname=NAME              Interface name (mandatory argument)
  -c, --cert=FILE                Public certificate (default: cert.pem)
  -k, --key=FILE                 Private key (default: key.pem)
  -v, --vlanid=[-1, 255]         Set VLANID on packets sent over TLS (default: -1)
                                 vlandid=-1 left the vlan header unchanged
                                 vlanid=0 remove the vlan header
  -p, --pid=FILE                 Write the daemon pid in this file (default: /var/run/brtls.pid)
  -d, --daemon                   Daemonize the program after startup
  -s, --server                   Run in server mode
  -h, --help                     Display this help
  -V, --version                  Display the version
```

# Examples:
Bridge eth0 interface on server with eth1 interface on client:
```
root@server: make cert                          # generate certificates
root@server: scp *.pem client:.                 # share certificates with client
root@server: brtls -i eth0 -s 0.0.0.0 9000      # start bridge over tls on server side
root@client: brtls -i eth1 $serverhostname 9000 # start bridge over tls on client side
```

