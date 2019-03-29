# -*- coding: utf-8 -*
'''
	A very simple raw socket implementation in Python
'''

import sys, socket
from struct import *
import random
from ip_header import *
from tcp_header import *
from  http_header import *
from util import get_host_ip


host, path = urlparse(sys.argv[1])


def filter_packet(data):
    global ip_dest
    if data == '': return False

    ip_header = data[0:20]
    iph = unpack('!BBHHHBBH4s4s', ip_header)
    source_address = socket.inet_ntoa(iph[8])
    print source_address

    if source_address != ip_dest:
        return False

    if validate_incoming(data[0:20], host):
        print "Invalid packet, IP check fail"

    return True

def recv_packet(received_socket):
    while True:
        data = received_socket.recv(65565)
        if filter_packet(data):
            return data

def send_sync(ip_header, send_socket, seqc, port):
    tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, port, '', seqc, 0, [0, 0, 0, 0, 1, 0])
    packet = ip_header + tcp_header
    send_socket.sendto(packet, (ip_dest, 0))


def send_ack(ip_header, send_socket, seqc, seqs, port):
    tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, port, '', seqc, seqs, [0, 1, 0, 0, 0, 0])
    packet = ip_header + tcp_header
    send_socket.sendto(packet, (ip_dest, 0))

def send_fin(ip_header, send_socket, seqc, seqs, port):
    tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, port, '', seqc, seqs, [0, 0, 0, 0, 0, 1])
    packet = ip_header + tcp_header
    send_socket.sendto(packet, (ip_dest, 0))


def send_http(ip_header, send_socket, seqc, seqs, http_header, port):
    tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, port, http_header, seqc, seqs, [0, 1, 1, 0, 0, 0])
    packet = ip_header + tcp_header + http_header
    send_socket.sendto(packet, (ip_dest, 0))


def main():
    try:
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        received_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error, msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    global ip_saddr, ip_daddr, ip_protocol, ip_dest, host, path

    ip_source = get_host_ip()  # local ip
    # host = socket.gethostbyname(url)
    ip_dest = socket.gethostbyname(host)  # try to send a packet to fakebook
    print ip_dest

    ip_saddr = socket.inet_pton(socket.AF_INET, ip_source)  # 两边的ip地址
    ip_daddr = socket.inet_pton(socket.AF_INET, ip_dest)
    ip_protocol = socket.IPPROTO_TCP  # 表示后面接的是tcp数据

    ip_header = construct_ip_header(ip_saddr, ip_daddr, ip_protocol)

    # first hand shake: send out sync
    port = send_socket.getsockname()[1]
    seqc = random.randint(1, 100000)
    send_sync(ip_header, send_socket, seqc, port)

    print "Sync packet sent"

    # get sync/ack back
    data = ''
    while not filter_packet(data):
        data = received_socket.recv(65565)
    seqs, tcp_ack_seq, tcp_flags = unpack_tcp(data)
    print "ack: " + str(seqs)

    # third hand shake, send out ack back
    seqc += 1
    seqs += 1
    send_ack(ip_header, send_socket, seqc, seqs, port)

    # send out http request
    request = construct_http_header(host, path)
    send_http(ip_header, send_socket, seqc, seqs, request, port)
    print 'sent http'
    http_buffer = ''

    fin_flag = 0
    data = {}  # dictionary to maintain the payload
    tear_down_success_flag = 0

    while (tear_down_success_flag != 1):

        recvPacket = recv_packet(received_socket)
        ipHeader = recvPacket[0:20]
        tcpHeader = recvPacket[20:40]
        ipHdr = unpack("!2sH8s4s4s", ipHeader)
        recv_length = ipHdr[1] - 40
        tcpHdr = unpack('!HHLLBBHHH', tcpHeader)
        fin_ack_psh_flag = tcpHdr[5] & 25
        new_seq = int(tcpHdr[3])
        new_ack = int(tcpHdr[2])
        if (recv_length != 0):  # segment that contains a payload
            unpack_arg = "!" + str(recv_length) + "s"
            app_part = unpack(unpack_arg, recvPacket[40:(recv_length + 40)])
            data[new_ack] = app_part[0]  # key -> ack_no and value -> data
            # if (verify_checksum(recvPacket, recv_length) == True):  # verify checksum
            send_ack(ip_header, send_socket, new_seq, new_ack + recv_length, port)

        if (fin_ack_psh_flag == 25):  # upon receiving FIN/PSH flag,
            tear_down_success_flag = 1  # gracefully tearing down the conn
            send_fin(ip_header, send_socket, new_seq, new_ack+recv_length+1, port)

    print data

    # # TODO: if request send back by multiple packet, should respond by ACK
    # while True:
    #     data = received_socket.recv(65565)
    #     if filter_packet(data):
    #         http_buffer += data
    #         seqs, tcp_ack_seq, tcp_flags = unpack_tcp(data)
    #         tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, port, request, seqc, seqs + 1,
    #                                           [0, 1, 0, 0, 0, 0])
    #         packet = ip_header + tcp_header + request
    #         # send_socket.sendto(packet, (ip_dest, 0))
    #         if tcp_flags[5] == 1:
    #             break
    #
    # print http_buffer
    #
    # # close connection here
    # tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, port, request, seqc, seqs + 1,
    #                                   [0, 1, 0, 0, 0, 0])
    # packet = ip_header + tcp_header + request
    # send_socket.sendto(packet, (ip_dest, 0))

    send_socket.close()
    received_socket.close()


ip_saddr = ''
ip_daddr = ''
ip_protocol = ''
ip_dest = ''
print host
main()
