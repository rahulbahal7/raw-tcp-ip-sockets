import sys, socket, ip, tcp
import fcntl
from struct import *
from random import randint
from utils import *
from httplib import HTTPResponse
from StringIO import StringIO
import signal

def signal_handler(signum, frame):
    raise Exception("Timed out!")

data_dict = {}
sequence_numbers = {}
cwnd_init = 1

# Class to validate URL and make initial request
class MakeRequest():
	def __init__(self,url):
		# print url.split('/')
		self.host = url.split('/')[2]
		# print "self.host --",self.host
		self.filename = url.split('/')[-1]
		if self.filename=="" or self.filename == self.host:
			self.filename = "index.html"
		# print "filename is ", self.filename
		# print self.host

class FakeSocket():
    def __init__(self, response_str):
        self._file = StringIO(response_str)
    def makefile(self, *args, **kwargs):
        return self._file

# source = FakeSocket(http_response_str)
# response = HTTPResponse(source)
# response.begin()
# print "status:", response.status
# print "single header:", response.getheader('Content-Type')
# print "content:", response.read(len(http_response_str))

def create_send_sockets():
	#create a raw socket for sending the packets
	try:
	    send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	except socket.error , msg:
	    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	    sys.exit()
	return send_socket

def create_receive_socket():
	#receive socket
	try:
	    recv_socket= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	except socket.error , msg:
	    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	    sys.exit()
	return recv_socket

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915,  # SIOCGIFADDR
        pack('256s', ifname[:15]))[20:24]) 

# constructin the packet
def connection(url):
	packet = ''
	send_socket = create_send_sockets()
	recv_socket = create_receive_socket()
	source_ip = get_ip_address('en0')  # '192.168.0.110'
	request = MakeRequest(url)
	source_port = get_open_port()
	dest_ip = socket.gethostbyname(request.host)
	# initiating handshake
	send_Syn(source_ip,dest_ip,source_port)
	while True:
		signal.signal(signal.SIGALRM, signal_handler)
		signal.alarm(180)   # 180 seconds
		try:
		    response = recv_socket.recvfrom(65565)
		except Exception, msg:
		    print "Timed out!"
		    sys.exit(0)
		# print response
		[tcph, version, ihl, ttl, protocol, s_addr, d_addr, s_port, d_port, sequence, acknowledgement, tcph_length, data] = decrypt_packet(response)
		if source_port == tcph[1] and tcph[5]==0x012:
			# print "Found syn ack"
			break

	# print "syn ack check sum", my_checksum
	# print "my tcp header"
	# print my_tcp_header
	# print "checksum", tcp.checksum(my_tcp_header)
	server_acknowledgement = acknowledgement
	server_sequence = sequence
	client_sequence = server_acknowledgement
	client_acknowledgement = server_sequence+1
	# print "sending ack"
	send_Ack(source_ip, dest_ip, source_port, client_sequence, client_acknowledgement, 'ACK')

	# server_sequence = client_acknowledgement
	# server_acknowledgement = client_sequence +1

	# --------------------------------------------------
	download(url, request, source_ip, dest_ip, source_port, client_sequence, server_sequence, client_acknowledgement, server_acknowledgement, request.filename)

def make_get_request(url,host):
	position = url.find(host) + len(host)
	path = url[position:]
	# print "path---",path
	if path == "":
		path = "/"
	get_request = "GET "+path+" HTTP/1.0 \r\nHost: "+host+"\r\nConnection: keep-alive"+"\r\n\r\n"
	# print get_request
	return get_request

# ---------------------HANDSHAKE---------------------
def send_Syn(source_ip,dest_ip, source_port):
	s = create_send_sockets()
	ip_header = ip.construct_ip_header(source_ip,dest_ip)
	sequence_no = randint(0,32000)
	ack=0
	tcp_header=tcp.construct_tcp_header(source_ip,dest_ip,source_port,sequence_no,ack,'SYN','',cwnd_init)
	packet = ip_header + tcp_header
	s.sendto(packet, (dest_ip,80))
	s.close()
	return [sequence_no, ack]

def get_open_port():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("",0))
        s.listen(1)
        port = s.getsockname()[1]
        s.close()
        return port

def decrypt_packet(packet):
	#packet string from tuple
	packet = packet[0]     
	#take first 20 characters for the ip header
	ip_header = packet[0:20]    
	#now unpack them
	iph = unpack('!BBHHHBBH4s4s' , ip_header)    
	version_ihl = iph[0]
	version = version_ihl >> 4
	ihl = version_ihl & 0xF     
	iph_length = ihl * 4    
	ttl = iph[5]
	protocol = iph[6]
	s_addr = socket.inet_ntoa(iph[8]);
	d_addr = socket.inet_ntoa(iph[9]);
	# ip checksum to verify it
	ip.checksum(ip_header)    

	# print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
	# take the next 20 characters for tcp header
	tcp_header = packet[iph_length:iph_length+20]
	#now unpack them 
	tcph = unpack('!HHLLBBHHH' , tcp_header)    
	source_port = tcph[0]
	dest_port = tcph[1]
	sequence = tcph[2]
	acknowledgement = tcph[3]
	doff_reserved = tcph[4]
	tcph_length = doff_reserved >> 4    
	# print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)    
	h_size = iph_length + tcph_length * 4
	data_size = len(packet) - h_size   
	#get data from the packet
	data = packet[h_size:]

	# for verifying tcp checksum
	# constructing the pseudo header
	placeholder = 0
	protocol = socket.IPPROTO_TCP
	pseudo_header = pack('!4s4sBBH' , s_addr, d_addr, placeholder , protocol, tcph_length * 4 + len(data))
	# calculating the tcp checksum
	tcp.checksum(pseudo_header + tcp_header + data)
	
	return[tcph, version, ihl, ttl, protocol, s_addr, d_addr, source_port, dest_port, sequence, acknowledgement, tcph_length, data]

def send_Ack(source_ip, dest_ip, source_port, sequence, acknowledgement,pkt_type):
	send_socket = create_send_sockets()
	ip_header = ip.construct_ip_header(source_ip,dest_ip)
	# print sequence
	# print acknowledgement
	# print dest_ip
	# print source_port
	tcp_header = tcp.construct_tcp_header(source_ip, dest_ip, source_port,sequence,acknowledgement,pkt_type,'',4000)
	packet = ip_header+tcp_header
	send_socket.sendto(packet, (dest_ip,80))
	# recv_socket = create_receive_socket()
	# response = recv_socket.recvfrom(65565)
	# decrypt_packet(response)

# def download(url, request, source_ip, dest_ip, source_port, client_sequence, server_sequence, client_acknowledgement, server_acknowledgement):
# 	get_request = make_get_request(url,request.host)
# 	# print "length of get -------", len(get_request)
# 	ip_header = ip.construct_ip_header(source_ip,dest_ip)
# 	tcp_header = tcp.construct_tcp_header(source_ip, dest_ip, source_port,client_sequence,client_acknowledgement,'PSHACK',get_request)
# 	packet = ip_header+tcp_header+get_request
# 	send_socket = create_send_sockets()
# 	send_socket.sendto(packet, (dest_ip,80))
# 	recv_socket = create_receive_socket()
	
# 	# Get the 3 initial packets from PUSH ACK
# 	count=0
# 	flag=0
# 	max_seq_data=''
# 	max_sequence =0
# 	max_acknowledgement=0
# 	while count<4:
# 		response = recv_socket.recvfrom(65565)
# 		# print "response----",response
# 		# response = recv_socket.recvfrom(65565)
# 		# print "response----",response
# 		# response = recv_socket.recvfrom(65565)
# 		# print "response----",response
# 		# response = recv_socket.recvfrom(65565)
# 		# print "response----",response
# 		# print "response -------",response
# 		[tcph, version, ihl, ttl, protocol, s_addr, d_addr, s_port, d_port, sequence, acknowledgement, tcph_length, data] = decrypt_packet(response)

# 		if(source_port == tcph[1]):
# 			server_sequence_new=str(sequence)+"."+str(len(data))
# 			data_dict.update({server_sequence_new:data})
# 			sequence_numbers.update({sequence:acknowledgement})
# 			# print "data ----",data
			
# 			max_sequence = max(sequence,max_sequence)
# 			if max_sequence == sequence:
# 				flag=1
# 			if flag == 1:
# 				max_seq_data=data
# 			flag=0
# 			max_acknowledgement = max(acknowledgement,max_acknowledgement)
		
# 		count+=1
# 	# expected acknowledgement from server after get request is sent to it
# 	new_seq = len(get_request)+client_sequence
# 	packet_type = tcph[5]
# 	packet_dest_port = tcph[1]
# 	print "push ack server sequence--", sequence
# 	# print "acknowledgement:",acknowledgement
# 	# print "new_seq:",new_seq
# 	# print "sequence of ACK-----",sequence
# 	# print "data from ACK=------",data

# 	# server_sequence = server_sequence+1

# 	# print "new_ack:", sequence
# 	# print "data-dictionary ----",data_dict
# 	# print "sequence_numbers----",sequence_numbers
# 	print "max_sequence---",max_sequence,"-----data----",max_seq_data
	
# 	if source_port==packet_dest_port and packet_type==0x010 and acknowledgement==new_seq:
# 	 	receive_rest_data(source_ip,dest_ip, source_port, max_acknowledgement, max_sequence, max_seq_data)

def bin_search(list, target):
    if target not in list:
        return None
    list.sort()
    return list[list.index(target)-1]

# def receive_rest_data(source_ip,dest_ip, source_port, acknowledgement, sequence, data):

# 	# print "INSIDE RECEIVE REST DATA---------------------"
# 	client_sequence = acknowledgement
# 	client_acknowledgement = sequence + len(data)
# 	# print "client_acknowledgement - INITIAL:",client_acknowledgement
# 	# Receive the Data
# 	recv_socket = create_receive_socket()
# 	while True:
# 		#Send ACK and receive response
# 		send_Ack(source_ip, dest_ip, source_port, client_sequence, client_acknowledgement)
# 		count=0
# 		flag=0
# 		max_seq_data=''
# 		max_sequence =0
# 		max_acknowledgement=0
# 		while count<5:
# 			response = recv_socket.recvfrom(65565)
# 			# print "response----",response
# 			# response = recv_socket.recvfrom(65565)
# 			# print "response----",response
# 			# response = recv_socket.recvfrom(65565)
# 			# print "response----",response
# 			# response = recv_socket.recvfrom(65565)
# 			# print "response----",response
# 			# print "response -------",response
# 			[tcph, version, ihl, ttl, protocol, s_addr, d_addr, s_port, d_port, sequence, acknowledgement, tcph_length, data] = decrypt_packet(response)

# 			if(source_port == tcph[1]):
# 				server_sequence_new=str(sequence)+"."+str(len(data))
# 				data_dict.update({server_sequence_new:data})
# 				sequence_numbers.update({sequence:acknowledgement})
# 				# print "data ----",data
# 				max_sequence = max(sequence,max_sequence)
# 				if max_sequence == sequence:
# 					flag=1
# 				if flag == 1:
# 					max_seq_data=data
# 				flag=0
# 				max_acknowledgement = max(acknowledgement,max_acknowledgement)
			
# 			count+=1

# # ##########################################################################

# 		# send_Ack(source_ip, dest_ip, source_port, client_sequence, client_acknowledgement)
# 		# recv_socket = create_receive_socket()
# 		# response = recv_socket.recvfrom(65565)
		
# 		# #Decrypt the packet
# 		# [tcph, version, ihl, ttl, protocol, s_addr, d_addr, s_port, d_port,server_sequence, server_acknowledgement, tcph_length, data] = decrypt_packet(response)
# 		# print "server_sequence:",server_sequence

# 		# # check if the packet belongs to the client's port
# 		# if(source_port == tcph[1]):
# 		# 	print "---------------------------"
# 		# 	print "server_sequence---",server_sequence
# 		# 	print "data---",data
# 		# 	server_sequence_new=str(server_sequence)+"."+str(len(data))
# 		# 	data_dict.update({server_sequence_new:data})
# 		# 	sequence_numbers.update({server_sequence:server_acknowledgement})
# 		# 	print "---------------------------"



# 		#check for lost packets
# 		# if server_sequence == client_acknowledgement-1:
# 		# 	print "first chunk revceived!" 
# 		# else:
# 		# 	length = 0
# 			# number = bin_search(sequence_numbers.keys(),server_sequence)
# 			# reqd_data = [value for key,value in data_dict.items() if str(number) in key]
# 			# if reqd_data:
# 			# 	length = len(reqd_data[0])
# 			# 	if length + number == server_sequence:
# 			# 		# print "no lost sequence here"
# 			# 		pass
# 			# 	else:
# 			# 		pass
# 			# 		print "retransmit lost sequences here"
# 			# 		received_sequence=int(number)+int(length)
# 			# 		send_Ack(source_ip, dest_ip, source_port, client_sequence, number)
# 			# 		recv_socket = create_receive_socket()
# 			# 		response = recv_socket.recvfrom(65565)
# 			# 		[tcph, version, ihl, ttl, protocol, s_addr, d_addr, s_port, d_port,server_sequence, server_acknowledgement, tcph_length, data] = decrypt_packet(response)
# 			# 		print "server_sequence after retransmisison:",server_sequence				
# 			# 		if received_sequence == server_sequence:
# 			# 			print "received",server_sequence

# 				#calculate number of missing chunks and their starting seq's

# 				# print "(number+len) received:",received_sequence
# 				# print "client_acknowledgement",client_acknowledgement

# 				# while True:
# 				# 	send_Ack(source_ip, dest_ip, source_port, client_sequence, received_sequence)
# 				# 	recv_socket = create_receive_socket()
# 				# 	response = recv_socket.recvfrom(65565)
# 				# 	[tcph, version, ihl, ttl, protocol, s_addr, d_addr, s_port, d_port,server_sequence, server_acknowledgement, tcph_length, data] = decrypt_packet(response)
# 				# 	print "server_sequence after retransmisison:",server_sequence
# 				# 	if server_sequence == received_sequence+len(data):
# 				# 		print "pass"
# 				# 		break
# 				# while (number + length != server_sequence or source_port != tcph[1]):
# 				# 	send_Ack(source_ip, dest_ip, source_port, client_sequence, client_acknowledgement)
# 				# 	recv_socket = create_receive_socket()
# 				# 	response = recv_socket.recvfrom(65565)
# 				# 	[tcph, version, ihl, ttl, protocol, s_addr, d_addr, s_port, d_port,server_sequence, server_acknowledgement, tcph_length, data] = decrypt_packet(response)
# 					# send acks (TBD)
# 					# wait for that packet (TBD)
# 					# repeat (TBD)


# 		#check if FINACK is received
# 		if ((tcph[5] == 17 or tcph[5]==25) and source_port == tcph[1]):
# 			break
# 		client_sequence = max_acknowledgement
# 		client_acknowledgement = max_sequence + len(max_seq_data)

# 	final_data = ""
# 	for k, v in sorted(data_dict.items()):
# 		final_data += v

# 	print final_data







# def check_for_chunk(source_ip,dest_ip, source_port, sequence_numbers, data_dict, tcph, version, ihl, ttl, protocol, s_addr, d_addr, s_port, d_port,server_sequence, server_acknowledgement, tcph_length, data):
# 	# get lost packet sequences (check)
# 		# send acks (TBD)
# 		# wait for that packet (TBD)
# 		# repeat (TBD)
# 	for seq in sorted(data_dict):
# 		# print "SERVER SEQUENCE----"
# 		sequence_new = seq.split('.')
# 		# print sequence_new[0]
# 		# print sequence_new[1]
# 		next_sequence = int(sequence_new[0]) + int(sequence_new[1])
# 		print "next_sequence:",next_sequence

# 		if next_sequence in sequence_numbers:
# 			print next_sequence,"present"
# 		else:
# 			print next_sequence,"not present"
# 			print sequence_new[0]
# 			print "hhhh",sequence_numbers[int(sequence_new[0])]
# 			send_Ack(source_ip, dest_ip, source_port, int(sequence_new[0]), int(sequence_numbers[int(sequence_new[0])]))
# 			recv_socket = create_receive_socket()
# 			response = recv_socket.recvfrom(65565)
# 			[tcph, version, ihl, ttl, protocol, s_addr, d_addr, s_port, d_port,server_sequence, server_acknowledgement, tcph_length, data] = decrypt_packet(response)

# 			if next_sequence == server_sequence:
# 				print "recd"
# 				if(source_port == tcph[1]):
# 				# print "----------TCPH[5]----------",tcph[5]
# 				# print "CLIENT SEQUENCE-----",client_sequence,"SERVER SEQUENCE----",server_sequence
# 					server_sequence_new=str(server_sequence)+"."+str(len(data))
# 					data_dict.update({server_sequence_new:data})
# 					# sequence_numbers.append(server_sequence)
# 					sequence_numbers.update({server_sequence:server_acknowledgement})
# 			# sys.exit()
			# send acks
		

# ###########################FOR RETRANSMISSION###############################

def download(url, request, source_ip, dest_ip, source_port, client_sequence, server_sequence, client_acknowledgement, server_acknowledgement, filename):
	# get_request = make_get_request(url,request.host)
	# # print "length of get -------", len(get_request)
	# ip_header = ip.construct_ip_header(source_ip,dest_ip)
	# tcp_header = tcp.construct_tcp_header(source_ip, dest_ip, source_port,client_sequence,client_acknowledgement,'PSHACK',get_request)
	# packet = ip_header+tcp_header+get_request
	# send_socket = create_send_sockets()
	# send_socket.sendto(packet, (dest_ip,80))
	# recv_socket = create_receive_socket()
	
	# Get the 3 initial packets from PUSH ACK
	# count=0
	# flag=0
	# max_seq_data=''
	# max_sequence =0
	# max_acknowledgement=0
	# while count<4:
		
	# 	response = recv_socket.recvfrom(65565)
	# 	# print "response----",response
	# 	# response = recv_socket.recvfrom(65565)
	# 	# print "response----",response
	# 	# response = recv_socket.recvfrom(65565)
	# 	# print "response----",response
	# 	# response = recv_socket.recvfrom(65565)
	# 	# print "response----",response
	# 	# print "response -------",response
	# 	[tcph, version, ihl, ttl, protocol, s_addr, d_addr, s_port, d_port, sequence, acknowledgement, tcph_length, data] = decrypt_packet(response)

	# 	if(source_port == tcph[1] and tcph[5]==0x010):
	# 		server_sequence_new=str(sequence)+"."+str(len(data))
	# 		data_dict.update({server_sequence_new:data})
	# 		sequence_numbers.update({sequence:acknowledgement})
	# 		# print "data ----",data
			
	# 		max_sequence = max(sequence,max_sequence)
	# 		if max_sequence == sequence:
	# 			flag=1
	# 		if flag == 1:
	# 			max_seq_data=data
	# 		flag=0
	# 		max_acknowledgement = max(acknowledgement,max_acknowledgement)
	# 		packet_type = tcph[5]
	# 		packet_dest_port = tcph[1]
	# 	count+=1
	# # expected acknowledgement from server after get request is sent to it
	# new_seq = len(get_request)+client_sequence
	
	# print "push ack server sequence--", sequence
	# # print "acknowledgement:",acknowledgement
	# # print "new_seq:",new_seq
	# # print "sequence of ACK-----",sequence
	# # print "data from ACK=------",data

	# # server_sequence = server_sequence+1

	# # print "new_ack:", sequence
	# # print "data-dictionary ----",data_dict
	# # print "sequence_numbers----",sequence_numbers
	# print "max_sequence---",max_sequence,"-----data----",max_seq_data
	
	# if source_port==packet_dest_port and packet_type==0x010 and acknowledgement==new_seq:
	# 	print "ABT TO RECEIVE"
	#  	receive_rest_data(source_ip,dest_ip, source_port, max_acknowledgement, max_sequence, max_seq_data, filename)


	# client_sequence = acknowledgement
	# client_acknowledgement = sequence + len(data)
	# print "client_acknowledgement - INITIAL:",client_acknowledgement
	# Receive the Data
	# recv_socket = create_receive_socket()
	# print "in download"
	check_next_packets = {}
	flag = 0
	cwnd = cwnd_init 
	while True:

		if flag==0:
			get_request = make_get_request(url,request.host)
			# print "length of get -------", len(get_request)
			ip_header = ip.construct_ip_header(source_ip,dest_ip)
			tcp_header = tcp.construct_tcp_header(source_ip, dest_ip, source_port,client_sequence,client_acknowledgement,'PSHACK',get_request,cwnd_init)
			packet = ip_header+tcp_header+get_request
			send_socket = create_send_sockets()
			send_socket.sendto(packet, (dest_ip,80))
			recv_socket = create_receive_socket()
			flag =1
		else:
			#Send ACK and receive response
			# print "before send"
			send_Ack(source_ip, dest_ip, source_port, client_sequence, client_acknowledgement, 'ACK')
			# print "after send"
		count=0
		# flag=0
		# max_seq_data=''
		# max_sequence =0
		# max_acknowledgement=0
		# total_checksum = 0
		while count<3:
			# print "before receive"

			signal.signal(signal.SIGALRM, signal_handler)
			signal.alarm(180)   # 180 seconds
			try:
			    response = recv_socket.recvfrom(65565)
			except Exception, msg:
			    print "Timed out!"
			    sys.exit(0)
			
			# print "after receive but before decrypting"
			[tcph, version, ihl, ttl, protocol, s_addr, d_addr, s_port, d_port, sequence, acknowledgement, tcph_length, data] = decrypt_packet(response)

			# total_checksum += my_checksum
			# print "after receive"
			# ACK - 0X010, FIN PSH ACK - 0x019, PSH ACK - 0x018
			if(source_port == tcph[1] and (tcph[5]==0x010 or tcph[5]==0x018 or tcph[5]==0x019)):
				# server_sequence_new=str(sequence)+"."+str(len(data))

				check_next_packets.update({sequence:data})

				# data_dict.update({server_sequence_new:data})
				# sequence_numbers.update({sequence:acknowledgement})
				# print "data ----",data
				# max_sequence = max(sequence,max_sequence)
				# if max_sequence == sequence:
				# 	flag=1
				# if flag == 1:
				# 	max_seq_data=data
				# flag=0
				# max_acknowledgement = max(acknowledgement,max_acknowledgement)
			
			count+=1

		# print "total checksum", total_checksum
		latest_max_sequence = ""
		# first sequence
		if client_acknowledgement in check_next_packets.keys():
			latest_max_sequence = client_acknowledgement
			temp_data = check_next_packets[client_acknowledgement]
			
			data_dict.update({str(latest_max_sequence)+"."+str(len(temp_data)):temp_data})
			sequence_numbers.update({latest_max_sequence:acknowledgement})
			# second sequence
			if (client_acknowledgement + len(temp_data)) in check_next_packets.keys():
				latest_max_sequence = client_acknowledgement + len(temp_data)
				temp_data = check_next_packets[latest_max_sequence]

				data_dict.update({str(latest_max_sequence)+"."+str(len(temp_data)):temp_data})
				sequence_numbers.update({latest_max_sequence:acknowledgement})
				# third sequence
				if latest_max_sequence + len(temp_data) in check_next_packets.keys():
					latest_max_sequence = latest_max_sequence + len(temp_data)
					temp_data = check_next_packets[latest_max_sequence]

					data_dict.update({str(latest_max_sequence)+"."+str(len(temp_data)):temp_data})
					sequence_numbers.update({latest_max_sequence:acknowledgement})

 	# 	data_dict.update({server_sequence_new:data})
		# sequence_numbers.update({sequence:acknowledgement})
		# if latest_max_sequence=="":
		# 	latest_max_sequence=client_acknowledgement
		# 	print "latest max sequence is empty so assigning old seq:", latest_max_sequence
		# else:
		# 	print "latest max sequence is ", latest_max_sequence
		# 	print "new client acknowledgement is ", latest_max_sequence + len(check_next_packets[latest_max_sequence])

		#check if FINACK is received
		# print data_dict
		# sys.exit(0)
		if ((tcph[5] == 17 or tcph[5]==25) and source_port == tcph[1]):
			break
		
		client_sequence = acknowledgement
		if latest_max_sequence=="":
			client_acknowledgement = client_acknowledgement
			cwnd = cwnd_init
			# print "max sequence is empty so client acknowlegement is ",client_acknowledgement
		else:
			if cwnd == cwnd_init+1000:
				cwnd==cwnd_init+1000
			else:
				cwnd+=1
			client_acknowledgement = latest_max_sequence + len(check_next_packets[latest_max_sequence])
			# print "client acknowledgement is ", client_acknowledgement

		check_next_packets.clear()
		# client_acknowledgement = max_sequence + len(max_seq_data)

	final_data = ""
	for k, v in sorted(data_dict.items()):		
		final_data += v

	# print final_data
	send_Ack(source_ip, dest_ip, source_port, client_sequence+1, client_acknowledgement, 'FIN')
	if final_data == "":
		print "Server has sent a FIN"
	else:
		header = final_data.split("\r\n\r\n",1)[0]
		header_string = FakeSocket(header)
		header_response = HTTPResponse(header_string)
		header_response.begin()
		# print "header_response.status",header_response.status
		print str(type(header_response.status))
		# print "status:", header_response.status
		if header_response.status == 200:
			print "The status code is 200"
			content = final_data.split("\r\n\r\n",1)[1]
			with open(filename,'w') as f:
				f.write(content)
		else:
			print "The status code is not 200"


		# print "single header:", header_response.getheader('Content-Type')
		# print "content:", header_response.read(len(http_response_str))


	# content = final_data.split("\r\n\r\n",1)[1]
	# # print final_data

	# with open(filename,'w') as f:
	# 	f.write(content)

# def receive_rest_data(source_ip,dest_ip, source_port, acknowledgement, sequence, data, filename):

# 	# print "INSIDE RECEIVE REST DATA---------------------"
# 	client_sequence = acknowledgement
# 	client_acknowledgement = sequence + len(data)
# 	# print "client_acknowledgement - INITIAL:",client_acknowledgement
# 	# Receive the Data
# 	recv_socket = create_receive_socket()
# 	check_next_packets = {}
# 	while True:
# 		#Send ACK and receive response
# 		print "before send"
# 		send_Ack(source_ip, dest_ip, source_port, client_sequence, client_acknowledgement)
# 		print "after send"
# 		count=0
# 		flag=0
# 		# max_seq_data=''
# 		# max_sequence =0
# 		# max_acknowledgement=0
# 		while count<3:
# 			print "before receive"
# 			response = recv_socket.recvfrom(65565)
# 			print "after receive but before decrypting"
# 			[tcph, version, ihl, ttl, protocol, s_addr, d_addr, s_port, d_port, sequence, acknowledgement, tcph_length, data] = decrypt_packet(response)
# 			print "after receive"
# 			if(source_port == tcph[1] and (tcph[5]==0x010 or tcph[5]==0x019)):
# 				# server_sequence_new=str(sequence)+"."+str(len(data))

# 				check_next_packets.update({sequence:data})

# 				# data_dict.update({server_sequence_new:data})
# 				# sequence_numbers.update({sequence:acknowledgement})
# 				# print "data ----",data
# 				# max_sequence = max(sequence,max_sequence)
# 				# if max_sequence == sequence:
# 				# 	flag=1
# 				# if flag == 1:
# 				# 	max_seq_data=data
# 				# flag=0
# 				# max_acknowledgement = max(acknowledgement,max_acknowledgement)
			
# 			count+=1

# 		latest_max_sequence = ""
# 		# first sequence
# 		if client_acknowledgement in check_next_packets.keys():
# 			latest_max_sequence = client_acknowledgement
# 			temp_data = check_next_packets[client_acknowledgement]
			
# 			data_dict.update({str(latest_max_sequence)+"."+str(len(temp_data)):temp_data})
# 			sequence_numbers.update({latest_max_sequence:acknowledgement})
# 			# second sequence
# 			if (client_acknowledgement + len(temp_data)) in check_next_packets.keys():
# 				latest_max_sequence = client_acknowledgement + len(temp_data)
# 				temp_data = check_next_packets[latest_max_sequence]

# 				data_dict.update({str(latest_max_sequence)+"."+str(len(temp_data)):temp_data})
# 				sequence_numbers.update({latest_max_sequence:acknowledgement})
# 				# third sequence
# 				if latest_max_sequence + len(temp_data) in check_next_packets.keys():
# 					latest_max_sequence = latest_max_sequence + len(temp_data)
# 					temp_data = check_next_packets[latest_max_sequence]

# 					data_dict.update({str(latest_max_sequence)+"."+str(len(temp_data)):temp_data})
# 					sequence_numbers.update({latest_max_sequence:acknowledgement})

#  	# 	data_dict.update({server_sequence_new:data})
# 		# sequence_numbers.update({sequence:acknowledgement})
# 		# if latest_max_sequence=="":
# 		# 	latest_max_sequence=client_acknowledgement
# 		# 	print "latest max sequence is empty so assigning old seq:", latest_max_sequence
# 		# else:
# 		# 	print "latest max sequence is ", latest_max_sequence
# 		# 	print "new client acknowledgement is ", latest_max_sequence + len(check_next_packets[latest_max_sequence])

# 		#check if FINACK is received
# 		if ((tcph[5] == 17 or tcph[5]==25) and source_port == tcph[1]):
# 			break
		
# 		client_sequence = acknowledgement
# 		if latest_max_sequence=="":
# 			client_acknowledgement = client_acknowledgement
# 			print "max sequence is empty so client acknowlegement is ",client_acknowledgement
# 		else:
# 			client_acknowledgement = latest_max_sequence + len(check_next_packets[latest_max_sequence])
# 			print "client acknowledgement is ", client_acknowledgement

# 		check_next_packets.clear()
# 		# client_acknowledgement = max_sequence + len(max_seq_data)

# 	final_data = ""
# 	for k, v in sorted(data_dict.items()):
# 		final_data += v

# 	print "printing final data"
# 	print final_data

# 	print "starting my section"
# 	if final_data == "":
# 		print "Server has sent a FIN"
# 	else:
# 		header = final_data.split("\r\n\r\n",1)[0]
# 		header_string = FakeSocket(header)
# 		header_response = HTTPResponse(header_string)
# 		header_response.begin()
# 		print "status:", header_response.status
# 		print "single header:", header_response.getheader('Content-Type')
# 		print "content:", header_response.read(len(http_response_str))


# 	content = final_data.split("\r\n\r\n",1)[1]
# 	# print final_data

# 	with open(filename,'w') as f:
# 		f.write(content)


# ################## END OF  RETRANSMISSION ###################################