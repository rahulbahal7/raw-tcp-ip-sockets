import struct
import sys
import socket
import binascii
import commands
from utils import get_ip_address

#Sending Socket
def create_send_socket():
	try:
		send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
		send_sock.bind(('eth0',0))
	except socket.error , msg:
	    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	    sys.exit()
	return send_sock

#Sending Socket
def create_recv_socket():
	try: 
		recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
	except socket.error , msg:
	    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	    sys.exit()
	return recv_socket

# Get the IP of the Default Gateway
def get_gateway_ip():
	info = commands.getoutput('route -n').split('\n')
	default_gateway = ''
	for line in info:
		s = line.split()
		if s[0] == '0.0.0.0':
			default_gateway = s[1]
			break
	return default_gateway

# Get the MAC address of the Localhost
def mac_of_localhost():
	local_mac = commands.getoutput('ifconfig eth0 | grep HWaddr')
	info = local_mac.strip()
	local_mac = info[-17:]
	local_mac = local_mac.replace(':','')
	return local_mac

def construct_arp_packet(localhost_mac,localhost_ip,gateway_ip):
	dest_mac = '000000000000'
	op = 1
	#ethernet type
	htype = 0x0001
	# arp resolution
	ptype = 0x0800
	# length of mac 
	hlen=6
	# length of ip
	plen =4
	# print op
	pkt = struct.pack('!HHBBH6s4s6s4s', htype,ptype,hlen,plen,op,
										binascii.unhexlify(localhost_mac),
										socket.inet_aton(localhost_ip),
										binascii.unhexlify(dest_mac),
										socket.inet_aton(gateway_ip))
	return pkt

def construct_ethernet_packet(localhost_mac,dest, prot, data):
	packet = struct.pack('!6s6sH',binascii.unhexlify(dest),
								  binascii.unhexlify(localhost_mac),
								  prot)+data
	return packet

def decrypt_ethernet_packet(pkt,localhost_mac):
	x = struct.unpack('!6s6sH',pkt[0][:14])
	dst = binascii.hexlify(x[0])
	# print dst
	src = binascii.hexlify(x[1])
	if dst == localhost_mac:
		return [src, dst, pkt[0][14:]]
	else:
		return [0,0,0]

def decrypt_arp_packet(pkt):


if __name__ == '__main__':
	send_socket = create_send_socket()
	recv_socket = create_recv_socket()
	gateway_ip = get_gateway_ip()
	localhost_mac = mac_of_localhost()

	#Get the Localhost IP
	localhost_ip = get_ip_address('eth0')
	# print localhost_mac+' '+str(len(localhost_mac))
	# print localhost_ip+' '+str(len(localhost_ip))
	# print gateway_ip+' '+str(len(gateway_ip))
	arp_packet = construct_arp_packet(localhost_mac,localhost_ip,gateway_ip)
	ethernet_packet = construct_ethernet_packet(localhost_mac,'ffffffffffff', 0x0806, arp_packet)
	send_socket.sendto(ethernet_packet,('eth0',0))

	gate_mac = ''
	while True:
		pkt = recv_socket.recvfrom(4096)
		[dst,src,data] = decrypt_ethernet_packet(pkt, localhost_mac)
		##### ELSE BREAK AFTER TIMEOUT ---- ########
		if src == localhost_mac:
			print dst
			gate_mac = dst
			decrypt_arp_packet(data)
		
	#get_source_mac(send_sock, recv_socket, gateway_ip, localhost_mac)
