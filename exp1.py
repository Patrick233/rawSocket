# -*- coding: utf-8 -*
'''
	A very simple raw socket implementation in Python
'''

import sys, socket
from struct import *
import random
import time

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

def construct_ip_header():
    # ip header
    ip_ver = 4  # ipv4
    ip_ihl = 5  # Header Length =5, 表示无options部分
    ip_dscp = 0  # 以前叫tos，现在叫dscp
    ip_total_len = 0  # left for kernel to fill
    ip_id = 22222  # fragment相关，随便写个
    ip_frag_offset = 0  # fragment相关
    ip_ttl = 255  # *nix下TTL一般是255
    ip_checksum = 0  # left for kernel to fill

    ip_ver_ihl = (ip_ver << 4) + ip_ihl  # 俩4-bit数据合并成一个字节

    print (ip_saddr, ip_daddr)
    # 按上面描述的结构，构建ip header。
    ip_header = pack('!BBHHHBBH4s4s', ip_ver_ihl, ip_dscp, ip_total_len, ip_id, ip_frag_offset, ip_ttl, ip_protocol,
                     ip_checksum, ip_saddr, ip_daddr)

    return ip_header


def construct_tcp_header(payload_data, tcp_seq, tcp_ack_seq, flags):
    tcp_sport = int(sys.argv[1])	# source port
    tcp_dport = 80		# destination port
    # tcp_seq = random.randint(1,100000)	# random sequence number
    # tcp_ack_seq = 0		# 32-bit ACK number。这里不准备构建ack包，故设为0
    tcp_data_offset = 5	# 和ip header一样，没option field
    # tcp flags
    tcp_flag_urg = flags[0]
    tcp_flag_ack = flags[1]
    tcp_flag_psh = flags[2]
    tcp_flag_rst = flags[3]
    tcp_flag_syn = flags[4]
    tcp_flag_fin = flags[5]

    tcp_window_size = 65535
    tcp_checksum = 0
    tcp_urgent_ptr = 0

    # 继续合并small fields
    tcp_offset_reserv = (tcp_data_offset << 4)
    tcp_flags = tcp_flag_fin + (tcp_flag_syn << 1) + (tcp_flag_rst << 2) + (tcp_flag_psh <<3) + (tcp_flag_ack << 4) + (tcp_flag_urg << 5)

    # 按上面描述的结构，构建tcp header。
    tcp_header = pack('!HHLLBBHHH' , tcp_sport, tcp_dport, tcp_seq, tcp_ack_seq, tcp_offset_reserv, tcp_flags, tcp_window_size, tcp_checksum, tcp_urgent_ptr)

    # 构建pseudo ip header
    psh_saddr = ip_saddr
    psh_daddr = ip_daddr
    psh_reserved = 0
    psh_protocol = ip_protocol
    psh_tcp_len = len(tcp_header) + len(payload_data)
    psh = pack('!4s4sBBH', psh_saddr, psh_daddr, psh_reserved, psh_protocol, psh_tcp_len)

    # 创建最终用于checksum的内容
    chk = psh + tcp_header + payload_data

    # 必要时追加1字节的padding
    if len(chk) % 2 != 0:
        chk += '\0'

    tcp_checksum = checksum(chk)

    # 重新构建tcp header，把checksum结果填进去
    tcp_header = pack('!HHLLBBHHH' , tcp_sport, tcp_dport, tcp_seq, tcp_ack_seq, tcp_offset_reserv, tcp_flags, tcp_window_size, tcp_checksum, tcp_urgent_ptr)
    return tcp_header

def unpack_ip(packet):
    ip_ver_ihl, ip_dscp, ip_total_len, ip_id, ip_frag_offset, ip_ttl, ip_protocol, ip_checksum, ip_saddr, ip_daddr = unpack('!BBHHHBBH4s4s', packet)
    print (ip_ver_ihl, ip_dscp, ip_total_len, ip_id, ip_frag_offset, ip_ttl, ip_protocol,
                     ip_checksum, ip_saddr, ip_daddr)

def unpack_tcp(data):

    tcp_header = data[20:40]
    tch = unpack('!HHLLBBHHH', tcp_header)
    tcp_seq = tch[2]
    tcp_ack_seq = tch[3]
    off_reserved = tch[4]
    tch_len = off_reserved >> 4

    tcp_flags = get_tcp_flags(tch[5])

    return tcp_seq, tcp_ack_seq, tcp_flags


def get_tcp_flags(flags):
    C = flags >> 7
    E = flags & 0x40
    E >>= 6
    U = flags & 0x20
    U >>= 5
    A = flags & 0x10
    A >>= 4
    P = flags & 0x8
    P >>= 3
    R = flags & 0x4
    R >>= 2
    S = flags & 0x2
    S >>= 1
    F = flags & 0x1

    return [U, A, P, R, S, F]

def unpack_http(data):

    http = data[40:]
    print http

def filter_packet(data):
    global ip_dest
    if data == '': return False

    ip_header = data[0:20]
    iph = unpack('!BBHHHBBH4s4s', ip_header)
    source_address = socket.inet_ntoa(iph[8])
    print source_address

    if source_address!= ip_dest:
        return False

    return True

def main():
    try:
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        received_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error, msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    global ip_saddr, ip_daddr, ip_protocol, ip_dest

    ip_source = get_host_ip()  # local ip
    ip_dest = socket.gethostbyname('cs5700.ccs.neu.edu')  # try to send a packet to fakebook
    print ip_dest

    ip_saddr = socket.inet_pton(socket.AF_INET, ip_source)  # 两边的ip地址
    ip_daddr = socket.inet_pton(socket.AF_INET, ip_dest)
    ip_protocol = socket.IPPROTO_TCP  # 表示后面接的是tcp数据

    payload_data = "Hey fackebook"

    ip_header = construct_ip_header()

    # first hand shake: send out sync
    # flags
    # tcp_flag_urg = flags[0]
    # tcp_flag_ack = flags[1]
    # tcp_flag_psh = flags[2]
    # tcp_flag_rst = flags[3]
    # tcp_flag_syn = flags[4]
    # tcp_flag_fin = flags[5]
    seqc = random.randint(1,100000)
    tcp_header = construct_tcp_header('', seqc, 0, [0,0,0,0,1,0])

    # 最终的tcp/ip packet！
    packet = ip_header + tcp_header
    # 发送出去
    send_socket.sendto(packet, (ip_dest, 0))
    print len(packet)
    print "packet sent"

    data = ''
    while not filter_packet(data):
        data = received_socket.recv(65565)

    seqs, tcp_ack_seq, tcp_flags = unpack_tcp(data)
    print "ack: " + str(seqs)
    #send out ack back
    seqc += 1
    seqs += 1
    tcp_header = construct_tcp_header('', seqc, seqs, [0, 1, 0, 0, 0, 0])
    packet = ip_header + tcp_header
    # time.sleep(0.5)
    send_socket.sendto(packet, (ip_dest, 0))

    request = "GET / HTTP/1.1\r\nHost: cs5700.ccs.neu.edu\r\nAccept: */*\r\nConnection: Keep-Alive\r\nUser-Agent: curl/7.58.0\r\n\r\n"
    tcp_header = construct_tcp_header(request, seqc, seqs, [0, 0, 1, 0, 0, 0])
    packet = ip_header + tcp_header + request
    send_socket.sendto(packet, (ip_dest, 0))
    print 'sent http'
    http_buffer = ''

    while True:
        data = received_socket.recv(65565)
        if filter_packet(data):
            http_buffer += data
            seqs, tcp_ack_seq, tcp_flags = unpack_tcp(data)
            if tcp_flags[5] == 1:
                break

    print http_buffer
ip_saddr = ''
ip_daddr = ''
ip_protocol = ''
ip_dest = ''

main()
