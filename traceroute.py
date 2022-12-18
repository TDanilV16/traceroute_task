from ipwhois import IPWhois, exceptions
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest

import traceroute_parser


class Traceroute:
    def __init__(self, host, timeout, port, TTL, verbose, packets_type):
        self.host = host
        self.IPv6 = ":" in host
        self.timeout = timeout
        self.port = port
        self.TTL = TTL
        self.verbose = verbose
        packets_types = {"tcp": self.tcp, "udp": self.udp, "icmp": self.icmp}
        self.execute = packets_types[packets_type]

    def tcp_udp(self, protocol, i):
        if self.IPv6:
            return IPv6(dst=self.host, hlim=i) / protocol(dport=self.port)
        return IP(dst=self.host, ttl=i) / protocol(dport=self.port)

    def tcp(self, i):
        return self.tcp_udp(TCP, i)

    def udp(self, i):
        return self.tcp_udp(UDP, i)

    def icmp(self, i):
        if self.IPv6:
            return IPv6(dst=self.host, hlim=i) / ICMPv6EchoRequest()
        return IP(dst=self.host, ttl=i) / ICMP()

    def run(self):
        asn = ""
        for ttl in range(1, self.TTL):
            package = self.execute(ttl)
            start_ping = time.time()
            reply = sr1(package, verbose=0, timeout=self.timeout)
            end_ping = round((time.time() - start_ping) * 1000)
            if self.verbose:
                if ttl == 1:
                    try:
                        print(f"{ttl} {reply.src} {end_ping} ms inverse lookup failed")
                        continue
                    except AttributeError:
                        print("Too fast! Try again! (Windows/Scapy internal bug)")
                        break
                try:
                    asn = IPWhois(reply.src).lookup_whois()['asn']
                except AttributeError:
                    asn = "Not found!"
                except exceptions.IPDefinedError:
                    asn = "Not found!"
            if reply is None:
                print(f"{ttl} *")
                break
            elif reply.haslayer(TCP) \
                    or (reply.type == 3 and reply.code == 3) \
                    or (reply.type == 0 and reply.code == 0) \
                    or (reply.type == 1 and reply.code == 4) \
                    or (reply.type == 129 and reply.code == 0):
                print(f"Done: {ttl} {reply.src} {end_ping} ms {asn}")
                break
            else:
                print(f"{ttl} {reply.src} {end_ping} ms {asn}")


if __name__ == '__main__':
    p = traceroute_parser.create_parser()
    args = p.parse_args()
    if ":" in args.host:
        host = p.args.host
    else:
        host = socket.gethostbyname(args.host)

    traceroute = Traceroute(
        host,
        args.timeout,
        args.port,
        args.TTL,
        args.verbose,
        args.packets_type
    )

    traceroute.run()
