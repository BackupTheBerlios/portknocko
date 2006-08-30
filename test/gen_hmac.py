import sys
import hmac
import md5
import socket

def gen_hmac(secret, ip):
	h = hmac.new(secret, digestmod = md5)
	h.update(socket.inet_aton(ip))
	print h.hexdigest()

if __name__ == '__main__':
	gen_hmac(sys.argv[1], sys.argv[2])
