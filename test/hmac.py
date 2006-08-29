import sys
import sha256
import socket

def hmac(secret, ip):
	print sha256.new(secret + socket.inet_aton(ip)).hexdigest()

if __name__ == '__main__':
	hmac(sys.argv[1], sys.argv[2])
