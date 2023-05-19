import socket
import os
from threading import Thread
import sys

class Proxy2Server(Thread):
    def __init__(self, host, port):
        super(Proxy2Server, self).__init__()
        self.client = None
        self.port = port
        self.host = host
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.connect((host, port))
        self.packetCount = 0
    def run(self):
        while True:
            self.packetCount = self.packetCount + 1
            data = self.server.recv(4096)
            if data:
                print("[{}({})] {}, packet count {}".format('server', self.port, sys.getsizeof(data), self.packetCount))
                print(data)
                self.client.sendall(data)
class Client2Proxy(Thread):
    def __init__(self, host, port):
        super(Client2Proxy, self).__init__()
        self.server = None
        self.port = port
        self.host = host
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(1)
        self.client, self.addr = sock.accept()
        self.packetCount = 0
    def run(self):
        while True:
            self.packetCount = self.packetCount + 1
            data = self.client.recv(4096)
            if data:
                print("[{}({}){}] {}, packet count {}".format('client', self.port, self.addr, sys.getsizeof(data), self.packetCount))
                self.server.sendall(data)
class Proxy(Thread):
    def __init__(self, from_host, to_host, port, to_port):
        super(Proxy, self).__init__()
        self.from_host = from_host
        self.to_host = to_host
        self.port = port
        self.to_port = to_port
    def run(self):
        while True:
            print("[proxy({})] setting up".format(self.port))
            self.c2p = Client2Proxy(self.from_host, self.port)
            self.p2s = Proxy2Server(self.to_host, self.to_port)
            print("[proxy({})] connection established".format(self.port))
            self.c2p.server = self.p2s.server
            self.p2s.client = self.c2p.client
            self.c2p.start()
            self.p2s.start()

master_server = Proxy('0.0.0.0', '192.168.29.128', 3001, 5000)
master_server.start()

while True:
    try:
        cmd = input()
        if cmd[:4] == 'quit':
            os._exit(0)
    except Exception as e:
        print(e)