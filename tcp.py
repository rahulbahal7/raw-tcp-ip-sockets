import socket
from struct import *


 # 0                   1                   2                   3
 #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 #   |          Source Port          |       Destination Port        |
 #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 #   |                        Sequence Number                        |
 #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 #   |                    Acknowledgment Number                      |
 #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 #   |  Data |           |U|A|P|R|S|F|                               |
 #   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 #   |       |           |G|K|H|T|N|N|                               |
 #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 #   |           Checksum            |         Urgent Pointer        |
 #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 #   |                    Options                    |    Padding    |
 #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 #   |                             data                              |
 #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    # print "messageeeeee ---------",msg
    for i in range(0, len(msg), 2):
    	# print "length ---",len(msg)
    	# print i
    	# print i+1
    	# print "msg[i]",msg[i]
    	# print "msg[i+1]",msg[i+1]

        # w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        w = ord(msg[i])
        if i+1<len(msg):
        	w = w+(ord(msg[i+1]) << 8 )
        s = s + w

    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);

    #complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

def construct_tcp_header(source_ip, dest_ip, source_port,sequence_no,ack,flag_type,data,cwnd):
	# tcp header fields
	tcp_source = source_port   # source port
	tcp_dest = 80   # destination port
	tcp_seq = sequence_no
	tcp_ack_seq = ack
	tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
	#tcp flags
	tcp_fin = 0
	tcp_syn = 0
	tcp_rst = 0
	tcp_psh = 0
	tcp_ack = 0
	tcp_urg = 0

	if flag_type == "FIN":
		tcp_fin = 1
	elif flag_type == "SYN":
		tcp_syn = 1
	elif flag_type == "ACK":
		tcp_ack = 1
	elif flag_type == "SYNACK":
		tcp_syn = 1
		tcp_ack = 1
	elif flag_type == "PSHACK":
		tcp_psh = 1
		tcp_ack = 1
	cwnd += 4000
	tcp_window = socket.htons (cwnd)    #   maximum allowed window size
	tcp_check = 0
	tcp_urg_ptr = 0

	tcp_offset_res = (tcp_doff << 4) + 0
	tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

	# the ! in the pack format string means network order
	tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

	#user_data = 'Hello, how are you'

	# pseudo header fields
	source_address = socket.inet_aton( source_ip )
	dest_address = socket.inet_aton(dest_ip)
	placeholder = 0
	protocol = socket.IPPROTO_TCP
	tcp_length = len(tcp_header) + len(data)

	psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
	psh = psh + tcp_header + data;

	# print psh
	tcp_check = checksum(psh)
	# print tcp_check
	#print tcp_checksum

	# make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
	tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
	return tcp_header

def tcp_check_verify(header):
	pass
