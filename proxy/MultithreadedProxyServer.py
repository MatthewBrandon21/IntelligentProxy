import requests
import signal
import socket
import threading
from threading import Thread
import time
import struct
import base64
from time import strftime, gmtime
import json
import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import os
import sys
import psutil
import logging
import numpy as np
import csv

class Server(Thread):
    def __init__(self, config):
        super(Server, self).__init__()

        # save specific proxy configuration based on thread constructor
        self.config = config

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
        self.udp_pair_list = []

        # UDP Proxy only need 1 thread (stateless connection)
        th_udp = threading.Thread(
            name="UDP Thread",
            target=self.proxy_udp_thread,
            args=(self.udpSocket, self.udp_server_address, self.config),
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
                args=(clientSocket, client_address, self.tcp_server_address, self.config),
            )

            # Running thread process in background
            # th.setDaemon(True)

            # Start TCP thread
            th.start()
        
        # Close socket if program close
        self.serverSocket.close()

    def proxy_tcp_thread(self, clientSocket, tcpClientAddress, tcpServerAddress, config):
        global networklogger

        # Cache observer
        is_cache = None

        # Connection state for observe two-way interaction, 0 means one-way interaction
        connection_state = 1
        
        # Data forwarding
        tcp_start_connection = time.monotonic()

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
                url="http://" + tcpServerAddress[0] + ":" + str(tcpServerAddress[1]) + url,
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
            
            # Observed cache is used
            is_cache = "true"

            # Sending from cache to the client
            clientSocket.send(self.Memory[url])

            connection_state = connection_state - 1

        # Doesn't exist in cache
        else:
            # Observed cache is not used
            is_cache = "false"

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
            server_packet_count = 0
            temp = b""
            while True:
                try:
                    data = proxy_client_sock.recv(config["BUFFER_SIZE"])
                except:
                    break
                if len(data) > 0:
                    temp += data
                    clientSocket.send(data)
                    server_packet_count = server_packet_count + 1
                else:
                    server_packet_count = server_packet_count + 1
                    break
            connection_state = connection_state - 1
            
            # Caching new data for next request
            try:
                if self.reqDict[url][0] >= 300:
                    if len(self.Memory) == 3:
                        self.Memory.pop(url, None)
                    self.Memory[url] = temp
            except:
                pass
        
        # Data logging
        tcp_end_connection = time.monotonic()
        networklogger.info(f'{"TCP"},{str((tcp_end_connection-tcp_start_connection))},{"NULL"},{"NULL"},{"NULL"},{"NULL"},{"NULL"},{str(1)},{str(len(req))},{str(server_packet_count)},{str(len(data))},{tcpClientAddress[0]},{str(tcpClientAddress[1])},{tcpServerAddress[0]},{str(tcpServerAddress[1])},{"success"},{url},{str(connection_state)}')

        # Decrease client number
        self.clientNum = self.clientNum - 1
        
        # Connection forwarded successfully
        exit(0)
    
    def proxy_udp_thread(self, udpSocket, udpServerAddress, config):
        global networklogger
        udp_client_address = None
        r_bytes = None

        # check if two-way interaction with the destination IP, if not 0 means a packet skipped or failed to response
        connection_state = 0

        # Waiting for UDP connection
        while True:
            # Data receive
            data, address = udpSocket.recvfrom(config["UDP_BUFFERSIZE"])

            # Data forwarding
            if address and data:
                destination_addr = self.check_pairing(address, udpServerAddress, len(data))
                self.my_print(["forwarded a message from ", address, "into address of ", str(destination_addr)], ["data = ", data])
                if destination_addr != None:
                    udpSocket.sendto(data, destination_addr)

            # # If new connection
            # if udp_client_address == None:
            #     udp_client_address = address
            #     udp_start_connection = time.monotonic()
            #     connection_state = 0
            
            # # If incoming connection from client
            # if address == udp_client_address:
            #     udpSocket.sendto(data, udpServerAddress)
            #     # Data logging
            #     r_bytes = len(data)
            #     connection_state = connection_state + 1
            
            # # If incoming connection from server
            # elif address == udpServerAddress:
            #     udpSocket.sendto(data, udp_client_address)

            #     connection_state = connection_state - 1

            #     # Data logging
            #     udp_end_connection = time.monotonic()
            #     networklogger.info(f'{"UDP"},{str((udp_end_connection-udp_start_connection))},{"NULL"},{"NULL"},{"NULL"},{"NULL"},{"NULL"},{str(1)},{str(r_bytes)},{str(1)},{str(len(data))},{udp_client_address[0]},{str(udp_client_address[1])},{address[0]},{str(address[1])},{"success"},{"NULL"},{str(connection_state)}')
                
            #     # Reset to accept new client connection
            #     udp_client_address = None
            #     r_bytes = 0
            
            # # If incoming not from server
            # else:
            #     print("Unknown source")
    
    def check_pairing(self, addr, udpServerAddress, data_bytes):
        # Check if existing connection
        for i in range(len(self.udp_pair_list)):
            if addr == self.udp_pair_list[i][0]:
                self.udp_pair_list[i][3] = self.udp_pair_list[i][3] + 1
                return self.udp_pair_list[i][1]
            if addr == self.udp_pair_list[i][1]:
                destination_addr = self.udp_pair_list[i][0]
                networklogger.info(f'{"UDP"},{str((time.monotonic() - self.udp_pair_list[i][2]))},{"NULL"},{"NULL"},{"NULL"},{"NULL"},{"NULL"},{str(1)},{str(self.udp_pair_list[i][4])},{str(1)},{str(data_bytes)},{self.udp_pair_list[i][0][0]},{str(self.udp_pair_list[i][0][1])},{addr[0]},{str(addr[1])},{"success"},{"NULL"},{str(self.udp_pair_list[i][3] - 1)}')
                self.udp_pair_list.pop(i)
                return destination_addr
        
        # new connection
        # if from server (must be already replied to client)
        if(addr == udpServerAddress):
            return None
        # if from client
        # client address, server address, initial time, initial connectionstate, initial connection size
        else:
            self.my_print(["new pair"], [addr, udpServerAddress])
            self.udp_pair_list.append([addr, udpServerAddress, time.monotonic(), 1, data_bytes])
            return udpServerAddress

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
        global networklogger
        # Waiting for ICMP connection
        while True:
            data, addr = self.icmpSocket.recvfrom(self.bufferSize)

            # Data parsing
            print("Packet from %r: %r" % (addr,data))
            icmp_header = data[20:28]
            type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)

            # Data logging
            print("type: [" + str(type) + "] code: [" + str(code) + "] checksum: [" + str(checksum) + "] p_id: [" + str(p_id) + "] sequence: [" + str(sequence) + "]")
            # networklogger.info(f'type:{str(type)}code:{str(code)}checksum:{str(checksum)}p_id:{str(p_id)}sequence:{str(sequence)}')
            networklogger.info(f'{"ICMP"},{"NULL"},{str(type)},{str(code)},{str(checksum)},{str(p_id)},{str(sequence)},{str(1)},{str(len(data))},{"NULL"},{"NULL"},{addr[0]},{str(addr[1])},{"NULL"},{"NULL"},{"PING"},{"NULL"},{"NULL"}')

def seedProxyConfiguration():
    configAll = {}
    count = 1
    try:
        file = open("ProxyConfig.json","r")
        data = json.load(file)
        file.close()

        for i in data['proxyConfiguration']:
            config = {}
            print(i)
            if("PROXY_HOST_NAME" in i):
                if(isinstance(i["PROXY_HOST_NAME"], str)):
                    config["PROXY_HOST_NAME"] = i["PROXY_HOST_NAME"]
                else:
                    print("Invalid PROXY_HOST_NAME")
                    config["PROXY_HOST_NAME"] = "0.0.0.0"
            else:
                print("Missing PROXY_HOST_NAME")
                config["PROXY_HOST_NAME"] = "0.0.0.0"

            if("PROXY_TCP_BIND_PORT" in i):
                if(type(i["PROXY_TCP_BIND_PORT"])==int):
                    config["PROXY_TCP_BIND_PORT"] = i["PROXY_TCP_BIND_PORT"]
                else:
                    print("Invalid PROXY_TCP_BIND_PORT")
                    config["PROXY_TCP_BIND_PORT"] = 3001
            else:
                print("Missing PROXY_TCP_BIND_PORT")
                config["PROXY_TCP_BIND_PORT"] = 3001
            
            if("PROXY_UDP_BIND_PORT" in i):
                if(type(i["PROXY_UDP_BIND_PORT"])==int):
                    config["PROXY_UDP_BIND_PORT"] = i["PROXY_UDP_BIND_PORT"]
                else:
                    print("Invalid PROXY_UDP_BIND_PORT")
                    config["PROXY_UDP_BIND_PORT"] = 3002
            else:
                print("Missing PROXY_UDP_BIND_PORT")
                config["PROXY_UDP_BIND_PORT"] = 3002
            
            if("WEBSERVER_HOST_NAME" in i):
                if(isinstance(i["WEBSERVER_HOST_NAME"], str)):
                    config["WEBSERVER_HOST_NAME"] = i["WEBSERVER_HOST_NAME"]
                else:
                    print("Invalid WEBSERVER_HOST_NAME")
                    config["WEBSERVER_HOST_NAME"] = "0.0.0.0"
            else:
                print("Missing WEBSERVER_HOST_NAME")
                config["WEBSERVER_HOST_NAME"] = "0.0.0.0"

            if("WEBSERVER_TCP_BIND_PORT" in i):
                if(type(i["WEBSERVER_TCP_BIND_PORT"])==int):
                    config["WEBSERVER_TCP_BIND_PORT"] = i["WEBSERVER_TCP_BIND_PORT"]
                else:
                    print("Invalid WEBSERVER_TCP_BIND_PORT")
                    config["WEBSERVER_TCP_BIND_PORT"] = 5000
            else:
                print("Missing WEBSERVER_TCP_BIND_PORT")
                config["WEBSERVER_TCP_BIND_PORT"] = 5000
            
            if("WEBSERVER_UDP_BIND_PORT" in i):
                if(type(i["WEBSERVER_UDP_BIND_PORT"])==int):
                    config["WEBSERVER_UDP_BIND_PORT"] = i["WEBSERVER_UDP_BIND_PORT"]
                else:
                    print("Invalid WEBSERVER_UDP_BIND_PORT")
                    config["WEBSERVER_UDP_BIND_PORT"] = 5005
            else:
                print("Missing WEBSERVER_UDP_BIND_PORT")
                config["WEBSERVER_UDP_BIND_PORT"] = 5005
            
            if("MAX_REQUEST_LEN" in i):
                if(type(i["MAX_REQUEST_LEN"])==int):
                    config["MAX_REQUEST_LEN"] = i["MAX_REQUEST_LEN"]
                else:
                    print("Invalid MAX_REQUEST_LEN")
                    config["MAX_REQUEST_LEN"] = 1000
            else:
                print("Missing MAX_REQUEST_LEN")
                config["MAX_REQUEST_LEN"] = 1000
            
            if("BUFFER_SIZE" in i):
                if(type(i["BUFFER_SIZE"])==int):
                    config["BUFFER_SIZE"] = i["BUFFER_SIZE"]
                else:
                    print("Invalid BUFFER_SIZE")
                    config["BUFFER_SIZE"] = 1048576
            else:
                print("Missing BUFFER_SIZE")
                config["BUFFER_SIZE"] = 1048576
            
            if("CONNECTION_TIMEOUT" in i):
                if(type(i["CONNECTION_TIMEOUT"])==int):
                    config["CONNECTION_TIMEOUT"] = i["CONNECTION_TIMEOUT"]
                else:
                    print("Invalid CONNECTION_TIMEOUT")
                    config["CONNECTION_TIMEOUT"] = 20
            else:
                print("Missing CONNECTION_TIMEOUT")
                config["CONNECTION_TIMEOUT"] = 20
            
            if("CONCURRENT_CONNECTION" in i):
                if(type(i["CONCURRENT_CONNECTION"])==int):
                    config["CONCURRENT_CONNECTION"] = i["CONCURRENT_CONNECTION"]
                else:
                    print("Invalid CONCURRENT_CONNECTION")
                    config["CONCURRENT_CONNECTION"] = 10
            else:
                print("Missing CONCURRENT_CONNECTION")
                config["CONCURRENT_CONNECTION"] = 10
            
            if("UDP_BUFFERSIZE" in i):
                if(type(i["UDP_BUFFERSIZE"])==int):
                    config["UDP_BUFFERSIZE"] = i["UDP_BUFFERSIZE"]
                else:
                    print("Invalid UDP_BUFFERSIZE")
                    config["UDP_BUFFERSIZE"] = 1024
            else:
                print("Missing UDP_BUFFERSIZE")
                config["UDP_BUFFERSIZE"] = 1024
            
            if("ICMP_BUFFERSIZE" in i):
                if(type(i["ICMP_BUFFERSIZE"])==int):
                    config["ICMP_BUFFERSIZE"] = i["ICMP_BUFFERSIZE"]
                else:
                    print("Invalid ICMP_BUFFERSIZE")
                    config["ICMP_BUFFERSIZE"] = 1508
            else:
                print("Missing ICMP_BUFFERSIZE")
                config["ICMP_BUFFERSIZE"] = 1508
            
            configAll["proxy{}".format(count)] = config
            count = count + 1
        return configAll

    except FileNotFoundError:
        print("Rule file (firewallrules.json) not found, setting default values")
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
        configAll["proxy{}".format(count)] = config
        count = count + 1
        return configAll

def runProxy():
    global proxy_servers
    # If there is no proxy server created before
    if proxy_servers:
        try:
            print("Stopping current proxy thread")
            for i in proxy_servers:
                i.join()
            proxy_servers = []
        except:
            print("Proxy cannot stop")
    configAll = seedProxyConfiguration()
    for config_id, config in configAll.items():
        print("creating proxy: ", config_id)
        _proxy_server = Server(config)
        _proxy_server.start()
        proxy_servers.append(_proxy_server)

def restart_program():
    print("Restarting Program")
    try:
        p = psutil.Process(os.getpid())
        for handler in p.get_open_files() + p.connections():
            os.close(handler.fd)
    except Exception as e:
        print(e)
    python = sys.executable
    os.execl(python, python, *sys.argv)

def on_modified(event):
    print(f"{event.src_path} has been modified")
    restart_program()

class LoggerFilter(object):
    def __init__(self, level):
        self.__level = level
    def filter(self, logRecord):
        return logRecord.levelno == self.__level

# Data parser to machine learing dataset (will flush logfile every 5 second)
class DataParser(Thread):
    def __init__(self):
        super(DataParser, self).__init__()

        # Data parser configuration
        self.sleep_time = 5
        self.file_name = "network.log"
        self.data_count = 21

    def run(self):
        while True:
            # Array for save raw data from file
            raw_datas = []

            # Read logfile
            network_log_file = open(self.file_name, 'r')
            network_lines = network_log_file.readlines()
            if(len(network_lines) != 0):
                for line in network_lines:
                    text = line.strip()
                    data = text.split(",")

                    # Check if data count is correct
                    if(len(data) == self.data_count):
                        raw_datas.append(data)
                    else:
                        print("Data parser input format wrong")
                        logging.debug("Data parser input format wrong")
                
                # Grouping data into same IP address and protocol
                ipaddresses = set(map(lambda x:x[14], raw_datas))
                protocols = set(map(lambda x:x[3], raw_datas))
                categoried_datas = [[[y for y in raw_datas if y[14]==x and y[3]==j] for x in ipaddresses]for j in protocols]

                # looping every each group (protocols x IP addresses)
                for protocol_data in categoried_datas:
                    if(len(protocol_data) != 0):
                        for ip_data in protocol_data:
                            if(len(ip_data) != 0):
                                timestamp = []
                                no_thread = []
                                msg_time = []
                                connection_time = []
                                icmp_type = []
                                icmp_code = []
                                icmp_checksum = []
                                icmp_p_id = []
                                sequence = []
                                r_packets = []
                                r_bytes = []
                                n_packets = []
                                n_bytes = []
                                port_src = []
                                ip_dest = []
                                port_dest = []
                                tcp_url = []
                                connection_state = []
                                total_connection_sum = len(ip_data)
                                for data in ip_data:
                                    if(len(data) != 0):
                                        if(data[0] != "NULL"):
                                            timestamp.append(float(data[0]))
                                        if(data[1] != "NULL"):
                                            no_thread.append(int(data[1]))
                                        if(data[2] != "NULL"):
                                            msg_time.append(int(data[2]))
                                        if(data[4] != "NULL"):
                                            connection_time.append(float(data[4]))
                                        if(data[5] != "NULL"):
                                            icmp_type.append(int(data[5]))
                                        if(data[6] != "NULL"):
                                            icmp_code.append(int(data[6]))
                                        if(data[7] != "NULL"):
                                            icmp_checksum.append(int(data[7]))
                                        if(data[8] != "NULL"):
                                            icmp_p_id.append(int(data[8]))
                                        if(data[9] != "NULL"):
                                            sequence.append(int(data[9]))
                                        if(data[10] != "NULL"):
                                            r_packets.append(int(data[10]))
                                        if(data[11] != "NULL"):
                                            r_bytes.append(int(data[11]))
                                        if(data[12] != "NULL"):
                                            n_packets.append(int(data[12]))
                                        if(data[13] != "NULL"):
                                            n_bytes.append(int(data[13]))
                                        if(data[15] != "NULL"):
                                            port_src.append(int(data[15]))
                                        if(data[16] != "NULL"):
                                            ip_dest.append(self.StringToBytes(data[16]))
                                        if(data[17] != "NULL"):
                                            port_dest.append(int(data[17]))
                                        if(data[19] != "NULL"):
                                            tcp_url.append(self.StringToBytes(data[19]))
                                        if(data[20] != "NULL"):
                                            connection_state.append(int(data[20]))
                                
                                # mean = np.mean(r_bytes)
                                
                                timestamp_std = np.std(timestamp)
                                no_thread_std = np.std(no_thread)
                                msg_time_std = np.std(msg_time)
                                connection_time_std = np.std(connection_time)
                                icmp_type_std = np.std(icmp_type)
                                icmp_code_std = np.std(icmp_code)
                                icmp_checksum_std = np.std(icmp_checksum)
                                icmp_p_id_std = np.std(icmp_p_id)
                                sequence_std = np.std(sequence)
                                r_packets_std = np.std(r_packets)
                                r_packets_sum = np.sum(r_packets)
                                r_bytes_std = np.std(r_bytes)
                                r_bytes_sum = np.sum(r_bytes)
                                n_packets_std = np.std(n_packets)
                                n_packets_sum = np.sum(n_packets)
                                n_bytes_std = np.std(n_bytes)
                                n_bytes_sum = np.sum(n_bytes)
                                port_src_std = np.std(port_src)
                                ip_dest_std = np.std(ip_dest)
                                port_dest_std = np.std(port_dest)
                                tcp_url_std = np.std(tcp_url)
                                connection_state_std = np.std(connection_state)
                                connection_state_sum = np.sum(connection_state)
                                ip_src = ip_data[0][14]
                                protocol = ip_data[0][3]
                                number_of_unique_url = len(np.unique(tcp_url))
                                number_of_unique_src_port = len(np.unique(port_src))
                                number_of_unique_dest_port = len(np.unique(port_dest))
                                number_of_unique_dest_ipaddress = len(np.unique(ip_dest))
                                total_connection = total_connection_sum

                                # Label : 1 Normal, 2 ICMP flood, 3 UDP flood, 4 TCP flood
                                label = 1

                                #Creating headers
                                randvar1 = "timestamp_std"
                                randvar2 = "no_thread_std"
                                randvar3 = "msg_time_std"
                                randvar4 = "connection_time_std"
                                randvar5 = "icmp_type_std"
                                randvar6 = "icmp_code_std"
                                randvar7 = "icmp_checksum_std"
                                randvar8 = "icmp_p_id_std"
                                randvar9 = "sequence_std"
                                randvar10 = "r_packets_std"
                                randvar11 = "r_packets_sum"
                                randvar12 = "r_bytes_std"
                                randvar13 = "r_bytes_sum"
                                randvar14 = "n_packets_std"
                                randvar15 = "n_packets_sum"
                                randvar16 = "n_bytes_std"
                                randvar17 = "n_bytes_sum"
                                randvar18 = "port_src_std"
                                randvar19 = "ip_dest_std"
                                randvar20 = "port_dest_std"
                                randvar21 = "tcp_url_std"
                                randvar22 = "connection_state_std"
                                randvar23 = "connection_state_sum"
                                randvar24 = "ip_src"
                                randvar25 = "protocol"
                                randvar26 = "number_of_unique_url"
                                randvar27 = "number_of_unique_src_port"
                                randvar28 = "number_of_unique_dest_port"
                                randvar29 = "number_of_unique_dest_ipaddress"
                                randvar30 = "total_connection"
                                randvar31 = "label"

                                header = []
                                header = [randvar1,randvar2,randvar3,randvar4,randvar5,randvar6,
                                          randvar7, randvar8, randvar9, randvar10, randvar11,
                                          randvar12, randvar13, randvar14, randvar15, randvar16,
                                          randvar17, randvar18, randvar19, randvar20, randvar21,
                                          randvar22, randvar23, randvar24, randvar25, randvar26,
                                          randvar27, randvar28, randvar29, randvar30, randvar31]

                                smart = []
                                smart = [timestamp_std,no_thread_std,msg_time_std,connection_time_std,icmp_type_std,
                                         icmp_code_std, icmp_checksum_std, icmp_p_id_std, sequence_std, r_packets_std,
                                         r_packets_sum, r_bytes_std, r_bytes_sum, n_packets_std, n_packets_sum,
                                         n_bytes_std, n_bytes_sum, port_src_std, ip_dest_std, port_dest_std, tcp_url_std,
                                         connection_state_std, connection_state_sum, ip_src, protocol, number_of_unique_url,
                                         number_of_unique_src_port, number_of_unique_dest_port, number_of_unique_dest_ipaddress,
                                         total_connection, label]
                                
                                # Append to dataset file
                                with open('dataset.csv', 'a') as datafile:
                                    writer = csv.writer(datafile, delimiter=",")
                                    # writer.writerow(header)
                                    writer.writerow(smart)

                                datafile.close()
            
            # Flush logfile
            with open(self.file_name, 'w'):
                pass

            # Flush data
            raw_datas = []

            # Sleep 5 second
            time.sleep(self.sleep_time)
    
    def StringToBytes(self, data):
        sum = 0
        arrbytes = bytes(data, 'utf-8')
        for i in arrbytes:
            sum = sum + i
        return(sum)

networklogger = None

proxy_servers = []

configListener = {
    "ICMP_BUFFERSIZE": 1508,
}

if __name__ == "__main__":
    #create a logger
    networklogger = logging.getLogger('networklogger')
    networklogger.setLevel(logging.INFO)
    networkloggerhandler = logging.FileHandler('network.log')
    networkloggerformatter = logging.Formatter('%(created)f,%(thread)d,%(msecs)d,%(message)s')
    networkloggerhandler.setFormatter(networkloggerformatter)
    #set filter to log only INFO lines
    networkloggerhandler.addFilter(LoggerFilter(logging.INFO))
    networklogger.addHandler(networkloggerhandler)

    # Initialize logging
    logging.basicConfig(filename='application.log', encoding='utf-8', level=logging.DEBUG,
                        format='%(created)f,%(thread)d,%(msecs)d,%(message)s')
    
    # Make sure logging file is empty
    with open('network.log', 'w'):
        pass

    # Initialize watchdog
    patterns = ["*"]
    ignore_patterns = None
    ignore_directories = False
    case_sensitive = True
    my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
    my_event_handler.on_modified = on_modified
    path = "ProxyConfig.json"
    go_recursively = True
    my_observer = Observer()
    my_observer.schedule(my_event_handler, path, recursive=go_recursively)
    my_observer.start()
    try:
        # Run Proxy
        runProxy()
        listener1 = Listener(configListener)
        listener1.start()
        dataParser1 = DataParser()
        dataParser1.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()
