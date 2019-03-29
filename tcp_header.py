# -*- coding: utf-8 -*
from struct import *
from util import checksum

    # flags
    # tcp_flag_urg = flags[0]
    # tcp_flag_ack = flags[1]
    # tcp_flag_psh = flags[2]
    # tcp_flag_rst = flags[3]
    # tcp_flag_syn = flags[4]
    # tcp_flag_fin = flags[5]

def construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, tcp_sport, payload_data, tcp_seq, tcp_ack_seq, flags):
    # tcp_sport = 2338
    tcp_dport = 80		# destination port
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

    # pack small fields
    tcp_offset_reserv = (tcp_data_offset << 4)
    tcp_flags = tcp_flag_fin + (tcp_flag_syn << 1) + (tcp_flag_rst << 2) + (tcp_flag_psh <<3) + (tcp_flag_ack << 4) + (tcp_flag_urg << 5)

    # construct tcp header。
    tcp_header = pack('!HHLLBBHHH' , tcp_sport, tcp_dport, tcp_seq, tcp_ack_seq, tcp_offset_reserv, tcp_flags, tcp_window_size, tcp_checksum, tcp_urgent_ptr)

    # pseudo ip header
    psh_saddr = ip_saddr
    psh_daddr = ip_daddr
    psh_reserved = 0
    psh_protocol = ip_protocol
    psh_tcp_len = len(tcp_header) + len(payload_data)
    psh = pack('!4s4sBBH', psh_saddr, psh_daddr, psh_reserved, psh_protocol, psh_tcp_len)

    # final check sum
    chk = psh + tcp_header + payload_data

    # 必要时追加1字节的padding
    if len(chk) % 2 != 0:
        chk += '\0'

    tcp_checksum = checksum(chk)

    # checksum again
    tcp_header = pack('!HHLLBBHHH' , tcp_sport, tcp_dport, tcp_seq, tcp_ack_seq, tcp_offset_reserv, tcp_flags, tcp_window_size, tcp_checksum, tcp_urgent_ptr)
    return tcp_header

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