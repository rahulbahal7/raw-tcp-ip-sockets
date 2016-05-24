import sys, socket, ip, tcp
import fcntl
import struct
from utils import *


# tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)


if __name__ == '__main__':
	# Check if the input is valid
	if len(sys.argv) != 2:
		sys.exit("Please provide valid number of arguments")
	url = sys.argv[1]
	connection(url)
	

