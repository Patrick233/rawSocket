# -*- coding: utf-8 -*
import socket
from urlparse import urlparse
import sys

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
        HOST_NAME = url_obj[1]
        PATH_NAME = url_obj[2]
        if (not PATH_NAME):
            PATH_NAME = '/'  # if no path_name, default is '/'
    else:
        print "Given URL is not in expected format\n"
        sys.exit()
    return HOST_NAME, PATH_NAME