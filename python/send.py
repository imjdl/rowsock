import socket, sys
from struct import *
import netifaces
from random import shuffle


class send():

    def __init__(self, dst_ips, dst_port, src_port=10086):
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error:
            sys.exit()
        self.dst_ips, self.mask = self.makeips(dst_ips=dst_ips)
        shuffle(self.dst_ips)
        self.dst_port = dst_port
        self.src_port = src_port
        self.source_ip = netifaces.ifaddresses('wlan0')[2][0]['addr']

    def packets(self, dst_ip, syn=1, ack=0):
        packet = ''

        # ip header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  # kernel will fill the correct total length
        ip_id = 54321  # Id of this packet
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0  # kernel will fill the correct checksum
        ip_saddr = socket.inet_aton(self.source_ip)  # Spoof the source ip address if you want to
        ip_daddr = socket.inet_aton(dst_ip)

        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        # the ! in the pack format string means network order
        ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto,
                         ip_check, ip_saddr, ip_daddr)

        # tcp header fields
        tcp_source = self.src_port  # source port
        tcp_dest = self.dst_port  # destination port
        tcp_seq = 454
        tcp_ack_seq = 0
        tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
        # tcp flags
        tcp_fin = 0
        tcp_syn = syn
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = ack
        tcp_urg = 0
        tcp_window = socket.htons(5840)  # maximum allowed window size
        tcp_check = 0
        tcp_urg_ptr = 0

        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

        # the ! in the pack format string means network order
        tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                          tcp_window, tcp_check, tcp_urg_ptr)

        # pseudo header fields
        source_address = socket.inet_aton(self.source_ip)
        dest_address = socket.inet_aton(dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)

        psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length);
        psh = psh + tcp_header
        tcp_check = self.checksum(psh)
        # print tcp_checksum

        # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
        tcp_header = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                          tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)

        # final full packet - syn packets dont have any data
        packet = ip_header + tcp_header
        return packet

    def sendpacket(self):
        print(self.dst_ips)
        while self.dst_ips:
            ip = self.dst_ips.pop()
            pack = self.packets(dst_ip=ip)
            self.s.sendto(pack, (ip, self.dst_port))

    def checksum(self, msg):
        s = 0
        for i in range(0, len(msg)-1, 2):
            tmp = (msg[i + 1]<<8) + msg[i]
            s += tmp
            s = (s & 0xffff) + (s >> 16)
        return ~s & 0xffff

    def makeips(self, dst_ips):
        netips, mask = dst_ips.split('/')
        if mask == '24':
            ips = netips.split('.')
            ips.pop()
            ips = ".".join(ips)
            return [ips + "." + str(i) for i in range(1,256)], mask
        if mask == '16':
            ips = netips.split('.')
            ips.pop()
            ips.pop()
            ips = ".".join(ips)
            return [ips + "."+ str(i) + "." + str(j) for i in range(1, 256) for j in range(1,256)], mask

    def __del__(self):
        self.s.close()


if __name__ == '__main__':
    s = send(dst_ips='192.168.1.1/24', dst_port=80)
    s.sendpacket()
