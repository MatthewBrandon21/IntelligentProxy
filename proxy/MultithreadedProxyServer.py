import requests
import signal
import socket
import threading
from threading import Thread
import time
import struct
import base64
from time import strftime, gmtime

class Server(Thread):
    def __init__(self, config):
        super(Server, self).__init__()
        # Force shutdown threads if program close
        signal.signal(signal.SIGINT, self.shutdown)

        # TCP proxy initialization
        # Socket creation
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serverSocket.bind((config["PROXY_HOST_NAME"], config["PROXY_TCP_BIND_PORT"]))
        self.tcp_server_address = ((config["WEBSERVER_HOST_NAME"], config["WEBSERVER_TCP_BIND_PORT"]))

        # number of concurrent socket connection
        self.serverSocket.listen(config["CONCURRENT_CONNECTION"])

        # For logging count of connections
        self.clientNum = 0
        
        # Caching storage
        self.reqDict = {}
        self.Memory = {}

        # UDP proxy initialization
        self.udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpSocket.bind((config["PROXY_HOST_NAME"], config["PROXY_UDP_BIND_PORT"]))
        self.udp_server_address = ((config["WEBSERVER_HOST_NAME"], config["WEBSERVER_UDP_BIND_PORT"]))

        # UDP Proxy only need 1 thread (stateless connection)
        th_udp = threading.Thread(
            name="UDP Thread",
            target=self.proxy_udp_thread,
            args=(self.udpSocket, self.udp_server_address, config),
        )

        # Running thread process in background
        # th.setDaemon(True)
        th_udp.start()

    def run(self):
        # Waiting for TCP connection
        while 1:
            # Accept incoming connetion from iptables
            (clientSocket, client_address) = self.serverSocket.accept()

            # Handling new client connection with new thread
            th = threading.Thread(
                name=self._getClientName(),
                target=self.proxy_tcp_thread,
                args=(clientSocket, self.tcp_server_address, config),
            )

            # Running thread process in background
            # th.setDaemon(True)

            # Start TCP thread
            th.start()
        
        # Close socket if program close
        self.serverSocket.close()

    def proxy_tcp_thread(self, clientSocket, tcpServerAddress, config):
        # Obtaining request
        req = clientSocket.recv(config["MAX_REQUEST_LEN"])
        str_req = str(req)

        # String parsing
        try:
            url = str_req.split("\n")[0].split(" ")[1]
        except:
            exit(0)

        # Removing the http part
        http_pos = url.find("://")
        if http_pos != -1:
            url = url[(http_pos + 3) :]

        # If response modified or not
        try:
            resp = requests.get(
                url=url,
                headers={
                    "If-Modified-Since": strftime(
                        "%a, %d %b %Y %H:%M:%S GMT", gmtime(0)
                    )
                },
            )
            sc = resp.status_code
        except:
            try:
                resp = requests.get(
                    url="http://" + url,
                    headers={
                        "If-Modified-Since": strftime(
                            "%a, %d %b %Y %H:%M:%S GMT", gmtime(0)
                        )
                    },
                )
                sc = resp.status_code
            except:
                sc = 200
        
        # Check requested data in caching memory
        if url in self.Memory.keys() and sc == 304:
            # If exists in cache and cache not expired
            if time.time() - self.reqDict[url][1] > 300:
                self.reqDict[url][0] = 0
            else:
                self.reqDict[url][0] += 1

            # Sending from cache to the client
            clientSocket.send(self.Memory[url])

        # Doesn't exist in cache
        else:
            if url in self.reqDict.keys():
                if time.time() - self.reqDict[url][1] > 300:
                    self.reqDict[url][0] = 0
                else:
                    self.reqDict[url][0] += 1
            else:
                self.reqDict[url] = [1, time.time()]

            # Establishing a connection between the proxy server and the requested server
            proxy_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_client_sock.settimeout(config["CONNECTION_TIMEOUT"])
            try:
                proxy_client_sock.connect(tcpServerAddress)
            except:
                exit(0)
            proxy_client_sock.sendall(req)

            # Redirecting data from server to the client
            temp = b""
            while True:
                try:
                    data = proxy_client_sock.recv(config["BUFFER_SIZE"])
                except:
                    break
                if len(data) > 0:
                    temp += data
                    clientSocket.send(data)
                else:
                    break
            
            # Caching new data for next request
            try:
                if self.reqDict[url][0] >= 300:
                    if len(self.Memory) == 3:
                        self.Memory.pop(url, None)
                    self.Memory[url] = temp
            except:
                pass
        
        # Connection forwarded successfully
        exit(0)
    
    def proxy_udp_thread(self, udpSocket, udpServerAddress, config):
        udp_client_address = None

        # Waiting for UDP connection
        while True:
            data, address = udpSocket.recvfrom(config["UDP_BUFFERSIZE"])

            # If new connection
            if udp_client_address == None:
                udp_client_address = address
            
            # If incoming connection from client
            if address == udp_client_address:
                udpSocket.sendto(data, udpServerAddress)
            
            # If incoming connection from server
            elif address == udpServerAddress:
                udpSocket.sendto(data, udp_client_address)

                # Reset to accept new client connection
                udp_client_address = None
            
            # If incoming not from server
            else:
                print("Unknown source")

    # Giving thread name by incrementing client connection
    def _getClientName(self):
        self.clientNum += 1
        return self.clientNum

    # Force shutting off server
    def shutdown(self, signum, frame):
        print("Server is now closing")
        print("Forcefully closing all currently active threads")
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
        exit(0)

class Listener(Thread):
    def __init__(self, config):
        super(Listener, self).__init__()
        
        # UDP listener initialization 
        self.icmpSocket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        self.icmpSocket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.bufferSize = config["ICMP_BUFFERSIZE"]

    def run(self):
        # Waiting for ICMP connection
        while True:
            data, addr = self.icmpSocket.recvfrom(self.bufferSize)

            # Data parsing
            print("Packet from %r: %r" % (addr,data))
            icmp_header = data[20:28]
            type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
            print("type: [" + str(type) + "] code: [" + str(code) + "] checksum: [" + str(checksum) + "] p_id: [" + str(p_id) + "] sequence: [" + str(sequence) + "]")

            # Data logging

config = {
    "PROXY_HOST_NAME": "0.0.0.0",
    "PROXY_TCP_BIND_PORT": 3001,
    "PROXY_UDP_BIND_PORT": 3002,
    "WEBSERVER_HOST_NAME": "127.0.0.1",
    "WEBSERVER_TCP_BIND_PORT": 5000,
    "WEBSERVER_UDP_BIND_PORT": 5005,
    "MAX_REQUEST_LEN": 1000,
    "BUFFER_SIZE": 1024 * 1024,
    "CONNECTION_TIMEOUT": 20,
    "CONCURRENT_CONNECTION": 10,
    "UDP_BUFFERSIZE": 1024,
    "ICMP_BUFFERSIZE": 1508,
}

config2 = {
    "PROXY_HOST_NAME": "0.0.0.0",
    "PROXY_TCP_BIND_PORT": 3003,
    "PROXY_UDP_BIND_PORT": 3004,
    "WEBSERVER_HOST_NAME": "127.0.0.1",
    "WEBSERVER_TCP_BIND_PORT": 80,
    "WEBSERVER_UDP_BIND_PORT": 5005,
    "MAX_REQUEST_LEN": 1000,
    "BUFFER_SIZE": 1024 * 1024,
    "CONNECTION_TIMEOUT": 20,
    "CONCURRENT_CONNECTION": 10,
    "UDP_BUFFERSIZE": 1024,
    "ICMP_BUFFERSIZE": 1508,
}

config3 = {
    "ICMP_BUFFERSIZE": 1508,
}

master_server = Server(config)
master_server.start()
master_server2 = Server(config2)
master_server2.start()
listener1 = Listener(config3)
listener1.start()