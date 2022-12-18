import argparse


def main():
    create_parser()


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", dest="timeout", required=False, type=float, default=2)
    parser.add_argument("-p", dest="port", required=False, type=int, default=53)
    parser.add_argument("-n", dest="TTL", required=False, type=int, default=128)
    parser.add_argument("-v", dest="verbose", required=False, default=False, action="store_true")
    parser.add_argument("host", type=str)
    parser.add_argument(dest="packets_type", choices=["tcp", "udp", "icmp"])
    return parser


if __name__ == "__main__":
    main()
