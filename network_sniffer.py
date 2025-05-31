

import socket
import struct


conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

def ethernet_frame(data):
    dest, src, prototype = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest), get_mac_addr(src), socket.htons(prototype), data[14:]

def get_mac_addr(bytes_addr):
    
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

while True:
    raw_data, addr = conn.recvfrom(65536)
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    print('\n=== Ethernet Frame ===')
    print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

    if eth_proto == 8:  # IPv4
        version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
        print('=== IPv4 Packet ===')
        print(f'Version: {version}, TTL: {ttl}, Protocol: {proto}')
        print(f'Source IP: {src}, Destination IP: {target}')

