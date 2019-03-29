# -*- coding: utf-8 -*
import socket

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