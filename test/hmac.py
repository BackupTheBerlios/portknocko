import sys
import md5
import socket

def hmac(ip, secret):
	print md5.new(socket.inet_aton(ip) + secret).digest()

if __name__ == '__main__':
	hmac(sys.argv[1], sys.argv[2])
