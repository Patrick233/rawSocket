# -*- coding: utf-8 -*
from struct import *
import socket
from util import *
import random

def construct_ip_header(ip_saddr, ip_daddr, ip_protocol):
    # ip header
    ip_ver = 4  # ipv4
    ip_ihl = 5  # Header Length =5, 表示无options部分
    ip_dscp = 0  # 以前叫tos，现在叫dscp
    ip_total_len = 0  # left for kernel to fill
    ip_id = random.randint(10000,50000)  # randomly pick ID
    ip_frag_offset = 0  # fragment相关
    ip_ttl = 255  # *nix下TTL一般是255
    ip_checksum = 0  # left for kernel to fill

    ip_ver_ihl = (ip_ver << 4) + ip_ihl  # 俩4-bit数据合并成一个字节

    print (ip_saddr, ip_daddr)
    # 按上面描述的结构，构建ip header。
    ip_header = pack('!BBHHHBBH4s4s', ip_ver_ihl, ip_dscp, ip_total_len, ip_id, ip_frag_offset, ip_ttl, ip_protocol,
                     ip_checksum, ip_saddr, ip_daddr)

    return ip_header

def unpack_ip(packet):
    ip_ver_ihl, ip_dscp, ip_total_len, ip_id, ip_frag_offset, ip_ttl, ip_protocol, ip_checksum, ip_saddr, ip_daddr = unpack('!BBHHHBBH4s4s', packet)
    return (ip_ver_ihl, ip_dscp, ip_total_len, ip_id, ip_frag_offset, ip_ttl, ip_protocol,
                     ip_checksum, ip_saddr, ip_daddr)


def validate_incoming_ip(data, host):
    header = unpack_ip(data)
    # validate that the incoming packet has the correct version
    check_version = header[0] >> 4 == 4
    # validate that the incoming packet has the correct protocol
    check_protocol = header[6] == socket.IPPROTO_TCP
    # validate that the incoming packet comes from valid source
    check_source = socket.inet_ntoa(header[8]) == socket.gethostbyname(host)
    # validate checksum
    check_header_checksum = header[7] == checksum(data)

    return check_version and check_protocol and check_source and check_source and check_header_checksum