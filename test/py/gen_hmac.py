import sys
import hmac
import md5
import socket
import struct
from time import time

def gen_hmac(secret, ip):
	epoch_mins = (long)(time()/60)
	h = hmac.new(secret, digestmod = md5)
	h.update(socket.inet_aton(ip))
	h.update(struct.pack("i", epoch_mins)) # "i" is for integer
	print h.hexdigest()

if __name__ == '__main__':
	gen_hmac(sys.argv[1], sys.argv[2])
