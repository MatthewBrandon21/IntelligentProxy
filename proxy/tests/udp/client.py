import socket

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8000
BUFFER_SIZE = 2 ** 10

MESSAGE = "client"
 
def run_client():
	client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	client_socket.sendto(MESSAGE, (SERVER_HOST, SERVER_PORT))
	data, address = client_socket.recvfrom(BUFFER_SIZE)
	print('[*] Server (%s) response: "%s"' % (str(address), data))

if __name__ == '__main__':
	print('[*] Running UDP client...')
	run_client()