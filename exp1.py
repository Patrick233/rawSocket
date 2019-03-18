import socket
import sys

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error , msg:
	print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	sys.exit()

ip_source = '10.0.2.15'
ip_dest = '64.4.11.42'

ip_ver = 4			# ipv4
ip_ihl = 5
ip_dscp = 0
ip_total_len = 0		# left for kernel to fill
ip_id = 22222
ip_frag_offset = 0
ip_ttl = 255
ip_protocol = socket.IPPROTO_TCP
ip_checksum = 0			# left for kernel to fill
ip_saddr = socket.inet_pton(socket.AF_INET, ip_source)
ip_daddr = socket.inet_pton(socket.AF_INET, ip_dest)

ip_ver_ihl = (ip_ver << 4) + ip_ihl

# The form '!' is available for those poor souls who claim they can't
# remember whether network byte order is big-endian or little-endian.
ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_dscp, ip_total_len, ip_id, ip_frag_offset, ip_ttl, ip_protocol, ip_checksum, ip_saddr, ip_daddr)