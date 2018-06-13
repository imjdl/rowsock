import socket, sys
from struct import *
import netifaces



class getdata():

    def __init__(self, src_port=10086):
        self.src_port = src_port
        host = netifaces.ifaddresses('wlan0')[2][0]['addr']
        try:
            self.sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.sniffer.bind((host, self.src_port))
            self.sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except socket.error:
            sys.exit()

    def recv(self):
        while True:
            raw_buffer = self.sniffer.recvfrom(65535)[0]
            dst_port, src_port = self.getTCP(raw_buffer[20:40])
            if dst_port == self.src_port:
                dst_ip = self.getIP(raw_buffer[:20])
                print(dst_ip ,":", src_port)

    def getIP(self, data):
        iph = unpack('!BBHHHBBH4s4s', data)
        version = iph[0] >> 4  # Version
        ihl = iph[0] * 0xF  # IHL
        iph_length = ihl * 4  # Total Length
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        return s_addr

    def getTCP(self, data):
        tcph = unpack('!HHLLBBHHH', data)
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        return dest_port, source_port

    def __del__(self):
        self.sniffer.close()

if __name__ == '__main__':
    get = getdata()
    get.recv()
