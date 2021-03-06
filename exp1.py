# -*- coding: utf-8 -*
'''
	A very simple raw socket implementation in Python
'''

import sys, socket
from struct import *
import random
import time


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
    tcp_header = construct_tcp_header(request, seqc, seqs, [0, 1, 1, 0, 0, 0])
    packet = ip_header + tcp_header + request
    send_socket.sendto(packet, (ip_dest, 0))
    print 'sent http'
    http_buffer = ''

    #TODO: if request send back by multiple packet, should respond by ACK
    while True:
        data = received_socket.recv(65565)
        if filter_packet(data):
            http_buffer += data
            seqs, tcp_ack_seq, tcp_flags = unpack_tcp(data)
            tcp_header = construct_tcp_header(request, seqc, seqs + 1, [0, 1, 0, 0, 0, 0])
            packet = ip_header + tcp_header + request
            send_socket.sendto(packet, (ip_dest, 0))
            if tcp_flags[5] == 1:
                break

    print http_buffer

    #close connection here
    tcp_header = construct_tcp_header(request, seqc, seqs+1, [0, 1, 0, 0, 0, 0])
    packet = ip_header + tcp_header + request
    send_socket.sendto(packet, (ip_dest, 0))

ip_saddr = ''
ip_daddr = ''
ip_protocol = ''
ip_dest = ''

main()
