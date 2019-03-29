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
from urlparse import urlparse

host = urlparse(sys.argv[1]).hostname
def filter_packet(data):
    global ip_dest
    if data == '': return False

    ip_header = data[0:20]
    iph = unpack('!BBHHHBBH4s4s', ip_header)
    source_address = socket.inet_ntoa(iph[8])
    print source_address

    if source_address!= ip_dest:
        return False

    if validate_incoming(data[0:20], host):
        print "Invalid packet, IP check fail"

    return True

def main():

    try:
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        received_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error, msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    global ip_saddr, ip_daddr, ip_protocol, ip_dest, host

    ip_source = get_host_ip()  # local ip
    # host = socket.gethostbyname(url)
    ip_dest = socket.gethostbyname(host)  # try to send a packet to fakebook
    print ip_dest

    ip_saddr = socket.inet_pton(socket.AF_INET, ip_source)  # 两边的ip地址
    ip_daddr = socket.inet_pton(socket.AF_INET, ip_dest)
    ip_protocol = socket.IPPROTO_TCP  # 表示后面接的是tcp数据

    ip_header = construct_ip_header(ip_saddr, ip_daddr, ip_protocol)

    # first hand shake: send out sync
    seqc = random.randint(1,100000)
    port = send_socket.getsockname()[1]
    print 'send out on port ' + str(port)
    tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, port, '', seqc, 0, [0,0,0,0,1,0])
    packet = ip_header + tcp_header
    send_socket.sendto(packet, (ip_dest, 0))

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
    tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, port, '', seqc, seqs, [0, 1, 0, 0, 0, 0])
    packet = ip_header + tcp_header
    send_socket.sendto(packet, (ip_dest, 0))

    # send out http request
    request = construct_http_header(host)
    tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, port, request, seqc, seqs, [0, 1, 1, 0, 0, 0])
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
            tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, port, request, seqc, seqs + 1, [0, 1, 0, 0, 0, 0])
            packet = ip_header + tcp_header + request
            #send_socket.sendto(packet, (ip_dest, 0))
            if tcp_flags[5] == 1:
                break

    print http_buffer

    #close connection here
    tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, port, request, seqc, seqs+1, [0, 1, 0, 0, 0, 0])
    packet = ip_header + tcp_header + request
    send_socket.sendto(packet, (ip_dest, 0))

    send_socket.close()
    received_socket.close()

ip_saddr = ''
ip_daddr = ''
ip_protocol = ''
ip_dest = ''
print host
main()
