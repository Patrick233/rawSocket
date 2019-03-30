# -*- coding: utf-8 -*
import socket
from urlparse import urlparse
import sys
from struct import *
def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

# def checksum(msg):
#     s = 0
#     for i in range(0, len(msg), 2):
#         w = (ord(msg[i]) << 8 ) + ord(msg[i+1])
#         s = carry_around_add(s, w)

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (ord(msg[i])<<8) + (ord(msg[i+1]))
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff

def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    print ip
    return ip

def parse_URL(url):
    url_obj = urlparse(url)
    if (url_obj[0] == 'http'):
        host = url_obj[1]
        path = url_obj[2]
        if (not path):
            path = '/'  # if no path_name, default is '/'
    else:
        print "Given URL is not in expected format\n"
        sys.exit()
    return host, path

def validate_checksum(packet, payload_len):
    ipHeader = packet[0:20]
    ipHdr = unpack("!BBHHHBBH4s4s", ipHeader)

    placeholder = 0
    tcp_length = ipHdr[2] - 20
    protocol = ipHdr[6]
    sourceIP = ipHdr[8]
    destIP = ipHdr[9]
    tcpHeader = packet[20:]
    unpack_arg = '!HHLLBBHHH' + str(payload_len) + 's'
    if (payload_len % 2 == 1):  # if the len is a odd number, add 1
        payload_len = payload_len + 1
    pack_arg = '!HHLLBBHHH' + str(payload_len) + 's'
    tcpHdr = unpack(unpack_arg, tcpHeader)
    received_tcp_segment = pack(pack_arg, tcpHdr[0], tcpHdr[1], tcpHdr[2], tcpHdr[3], tcpHdr[4], tcpHdr[5], tcpHdr[6], 0,
                                tcpHdr[8], tcpHdr[9])
    pseudo_hdr = pack('!4s4sBBH', sourceIP, destIP, placeholder, protocol, tcp_length)  # pseudo header
    total_msg = pseudo_hdr + received_tcp_segment
    checksum_from_packet = tcpHdr[7]
    tcp_checksum = checksum(total_msg)
    return (checksum_from_packet == tcp_checksum)