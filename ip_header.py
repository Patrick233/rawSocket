from struct import *

def construct_ip_header(ip_saddr, ip_daddr, ip_protocol):
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

def unpack_ip(packet):
    ip_ver_ihl, ip_dscp, ip_total_len, ip_id, ip_frag_offset, ip_ttl, ip_protocol, ip_checksum, ip_saddr, ip_daddr = unpack('!BBHHHBBH4s4s', packet)
    return (ip_ver_ihl, ip_dscp, ip_total_len, ip_id, ip_frag_offset, ip_ttl, ip_protocol,
                     ip_checksum, ip_saddr, ip_daddr)