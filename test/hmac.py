import sys
import md5
import socket

def hmac(secret, ip):
	print md5.new(secret + socket.inet_aton(ip)).digest()

if __name__ == '__main__':
	hmac(sys.argv[1], sys.argv[2])
