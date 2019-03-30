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
from util import *
import time
import thread

host, path = parse_URL(sys.argv[1])


def filter_packet(data):
    global ip_dest
    if data == '': return False

    ip_header = data[0:20]
    iph = unpack('!BBHHHBBH4s4s', ip_header)
    source_address = socket.inet_ntoa(iph[8])
    print source_address

    if source_address != ip_dest:
        return False

    if validate_incoming_ip(data[0:20], host):
        print "Invalid packet, IP check fail"
        return False

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


def send_fin_ack(ip_header, send_socket, seqc, seqs, port):
    tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, port, '', seqc, seqs, [0, 1, 0, 0, 0, 1])
    packet = ip_header + tcp_header
    send_socket.sendto(packet, (ip_dest, 0))


def send_http(ip_header, send_socket, seqc, seqs, http_header, port):
    tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, port, http_header, seqc, seqs,
                                      [0, 1, 1, 0, 0, 0])
    packet = ip_header + tcp_header + http_header
    send_socket.sendto(packet, (ip_dest, 0))


# Simple implementation of congestion window
def simple_congestion(send_socket, ip_header, pay_load, seqs, seqc, cwnd, mss):
    global current_idx, slow_start_flg, ip_dest
    last_segment = 0
    # if slow_start,then set cwnd = 1
    if (slow_start_flg == 1):
        slow_start_flg = 0
        cwnd = 1
    # else additive increase
    else:
        current_idx = current_idx + cwnd * mss  # max cwnd is 1000
    cwnd = min(2 * cwnd, 1000)
    if (len(pay_load) - current_idx <= 0):  # return if there is no more data to send
        return
    if (len(pay_load) - current_idx > cwnd * mss):
        buffer = pay_load[current_idx:(current_idx + cwnd)]  # collect data from send_string and put it in buffer
    else:
        buffer = pay_load[current_idx:]
        last_segment = 1
    tcp_header = construct_tcp_header(ip_saddr, ip_daddr, ip_protocol, send_socket.getsockname()[1], buffer, seqc, seqs,
                                      [0, 1, 1, 0, 0, 0])
    packet = ip_header + tcp_header
    send_socket.sendto(packet, (ip_dest, 0))
    thread.start_new_thread(time_out_for_thread,
                            (current_idx, len(pay_load),))  # start a thread that maintains timer
    if (last_segment == 1):
        return
    simple_congestion(send_socket, ip_header, pay_load, seqs, seqc + cwnd * mss, cwnd, mss)

def time_out_for_thread(index, len):
    global current_idx, slow_start_flg
    time.sleep(60)
    if (index == current_idx and current_idx < len):  # current index hasn't moved forward for 60s,
        slow_start_flg = 1  # enter slow start phase
    thread.exit()


def main():
    try:
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        received_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error, msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    global ip_saddr, ip_daddr, ip_protocol, ip_dest, host, path

    ip_source = get_host_ip()  # local ip
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

    # second hand shake: get sync/ack back
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
    # send out http with basic congestion control and mss = 1000 and start cws = 3
    #  simple_congestion(send_socket, ip_header, request, seqs, seqc, 3, 1000)
    send_http(ip_header, send_socket, seqc, seqs, request, port)

    http_buffer = ''

    data = {}  # dictionary to maintain the payload
    tear_down_success_flag = 0

    while (tear_down_success_flag != 1):

        recvPacket = recv_packet(received_socket)
        ipHeader = recvPacket[0:20]
        tcpHeader = recvPacket[20:40]
        ipHdr = unpack("!2sH8s4s4s", ipHeader)
        recv_length = ipHdr[1] - 40
        tcpHdr = unpack('!HHLLBBHHH', tcpHeader)
        flags = get_tcp_flags(tcpHdr[5])
        new_seq = int(tcpHdr[3])
        new_ack = int(tcpHdr[2])
        if (recv_length != 0):  # segment that contains a payload
            unpack_arg = "!" + str(recv_length) + "s"
            app_part = unpack(unpack_arg, recvPacket[40:(recv_length + 40)])
            data[new_ack] = app_part[0]  # key -> ack_no and value -> data
            if (validate_checksum(recvPacket, recv_length) == True):  # verify checksum
                send_ack(ip_header, send_socket, new_seq, new_ack + recv_length, port)

        # if (fin_ack_psh_flag == 25):  # upon receiving FIN/PSH flag,
        if (flags[5] == 1):
            tear_down_success_flag = 1  # gracefully tearing down the conn
            send_fin_ack(ip_header, send_socket, new_seq, new_ack + recv_length + 1, port)

    for key in sorted(data):
        http_buffer = http_buffer + data[key]

    http_buffer = http_buffer.split("log\r\n\r\n",1)[1]
    print http_buffer

    # write to file
    filename = ""
    for s in sys.argv[1].split('.'):
        for s1 in s.split('/'):
            filename += s1

    f = open(filename+".log", "w")
    f.write(http_buffer)
    f.close()

    send_socket.close()
    received_socket.close()


ip_saddr = ''
ip_daddr = ''
ip_protocol = ''
ip_dest = ''
current_idx, slow_start_flg = 0, 1
print host
main()
