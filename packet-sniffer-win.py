import dpkt, pcap
from scapy.all import *

def main():
    capture = sniff(prn=lambda x:x.summary(), count=10)
    for packet in capture:
        print(packet.show())

if __name__ == '__main__':
    main()