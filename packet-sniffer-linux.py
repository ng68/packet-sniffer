from struct import *
import socket
import sys

def get_ethernet_header(raw_data):
    #Destination MAC (6 bytes), Source MAC (6 bytes), and Ether Type (2 bytes)
    dest, src, etype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    eth_type = socket.htons(etype)
    data = raw_data[14:]
    return dest_mac, src_mac, eth_type, data

def get_ip_header(raw_data):
    version_header_length = raw_data[0]
    #Version is 4 bits after header length 
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src = get_ip(src)
    target = get_ip(target)
    data = raw_data[header_length:]
    return version, header_length, ttl, proto, src, target, data

def get_ip(addr):
 return '.'.join(map(str, addr))

def get_tcp_header(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

def main():
    print("Starting packet sniff...\n")
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    host = socket.gethostname()
    s.bind((host, 9999))
    while True:
        raw_data, address = s.recvfrom(65535)
        eth = get_ethernet_header(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))
        if eth[2] == 8:
            ipv4 = get_ip_header(ethp[4])
            print( '\t - ' + 'IPv4 Packet:')
            print('\t\t - ' + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4[1], ipv4[2], ipv4[3]))
            print('\t\t - ' + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4[4], ipv4[5], ipv4[6]))

            if ipv4[4] == 6:
                tcp = get_tcp_header(ipv4[7])
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp[4], tcp[5], tcp[6]))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN: {}'.format(tcp[7], tcp[8], tcp[9]))
                if len(tcp[10]) > 0:
                # HTTP
                    if tcp[0] == 80 or tcp[1] == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp[10])
                            http_info = str(http[10]).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp[10]))
                        else:
                            print(TAB_2 + 'TCP Data:')
                            print(format_multi_line(DATA_TAB_3, tcp[10]))
            
            elif ipv4[4] == 17:
                udp = udp_head(ipv4[7])
                print('\t -' + 'UDP Segment:')
                print('\t\t -' + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp[0], udp[1], udp[2]))

if __name__ == '__main__':
    main()