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
from csv import writer
import pandas as pd
import itertools

proxy_name = "node-proxy"

class Server(Thread):
    def __init__(self, config):
        super(Server, self).__init__()

        # save specific proxy configuration based on thread constructor
        self.config = config

        # Force shutdown threads if program close
        signal.signal(signal.SIGINT, self.shutdown)

        # define the available table for round robin load balancer
        column_names = ["type", "id", "privPolyId", "listenport", "ip_addr"]
        self.updated_available_server_table = pd.DataFrame(columns = column_names)
        self.policy_table = {}
        
        for i, server in enumerate(config["LIST_SERVER"]):
            ip_addr, listenport = server.split(",")
            self.available_server("1", str(i), "RoundRobbin", listenport, ip_addr)
        
        print(self.updated_available_server_table)
        print(self.policy_table)

        # TCP proxy initialization
        try:
            # Socket creation
            # AF_inet = IPv4 and SOCK_STREAM = TCP
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
        except Exception as e:
            print(f'Unable to create/re-use the TCP proxy socket. Error: {e}')
            logging.error(f'Unable to create/re-use the TCP proxy socket. Error: {e}')

        # UDP proxy initialization
        try:
            # AF_inet = IPv4 and SOCK_DGRAM = UDP
            self.udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udpSocket.bind((config["PROXY_HOST_NAME"], config["PROXY_UDP_BIND_PORT"]))
            self.udp_server_address = ((config["WEBSERVER_HOST_NAME"], config["WEBSERVER_UDP_BIND_PORT"]))
            self.udp_pair_list = []
        except Exception as e:
            print(f'Unable to create/re-use the UDP proxy socket. Error: {e}')
            logging.error(f'Unable to create/re-use the UDP proxy socket. Error: {e}')

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
                args=(clientSocket, client_address, self.config),
            )

            # Running thread process in background
            # th.setDaemon(True)

            # Start TCP thread
            th.start()
        
        # Close socket if program close
        self.serverSocket.close()
    
    def round_robin(self, iterable):
        return next(iterable)
    
    def available_server(self, type, id, privPolyId, listenport, ip_addr):        
        data = {
            "type": type,
            "id": id,
            "privPolyId": privPolyId,
            "listenport": listenport,
            "ip_addr": ip_addr,
        }

        self.updated_available_server_table = self.updated_available_server_table._append(data, ignore_index = True)
        policy_list = set(self.updated_available_server_table["privPolyId"].tolist())
        
        for policy in policy_list:
            self.policy_table[policy] = itertools.cycle(set(self.updated_available_server_table\
                    [self.updated_available_server_table["privPolyId"]==policy]["id"].tolist()))

    def proxy_tcp_thread(self, clientSocket, tcpClientAddress, config):
        global networklogger
        
        # Data forwarding
        tcp_start_connection = time.perf_counter()

        # Obtaining request
        try:
            req = clientSocket.recv(config["MAX_REQUEST_LEN"])
        except Exception as e:
            print(f'Waiting to recieve data error TCP. Error: {e}')
            logging.error(f'Waiting to recieve data error TCP. Error: {e}')
            exit(0)
        str_req = str(req)

        # do i need check if request len(req) == 0?

        # String parsing
        try:
            url = str_req.split("\n")[0].split(" ")[1]
        except:
            networklogger.info(f'{"TCP"},{str((time.perf_counter()-tcp_start_connection)*1000)},{str(len(req))},{tcpClientAddress[0]},{str(tcpClientAddress[1])},{"failed_parsing"},{str(0)},{str(0)}')
            exit(0)

        # Removing the http part
        http_pos = url.find("://")
        if http_pos != -1:
            url = url[(http_pos + 3) :]
        
        # Get server address from round robbin balancer
        target_host_id = self.round_robin(self.policy_table["RoundRobbin"])
        server_name = self.updated_available_server_table.loc[self.updated_available_server_table["id"]==target_host_id, "ip_addr"].values[0]
        server_port = int(self.updated_available_server_table.loc[self.updated_available_server_table["id"]==target_host_id, "listenport"].values[0])

        serverAddress = (server_name, server_port)

        if(config["ENABLE_CACHE"]):
            # If response modified or not
            try:
                resp = requests.get(
                    url="http://" + serverAddress[0] + ":" + str(serverAddress[1]) + url,
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
                    proxy_client_sock.connect(serverAddress)
                except:
                    print(f'Error connect to web server. Error: {e}')
                    logging.error(f'Error connect to web server. Error: {e}')
                    networklogger.info(f'{"TCP"},{str((time.perf_counter()-tcp_start_connection)*1000)},{str(len(req))},{tcpClientAddress[0]},{str(tcpClientAddress[1])},{"failed_web_server"},{url},{str(socket_timeout)}')
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
                tcp_end_connection = time.perf_counter()
                
                # Caching new data for next request
                try:
                    if self.reqDict[url][0] >= 300:
                        if len(self.Memory) == 3:
                            self.Memory.pop(url, None)
                        self.Memory[url] = temp
                except:
                    pass
        else:
            # Establishing a connection between the proxy server and the requested server
            proxy_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_client_sock.settimeout(config["CONNECTION_TIMEOUT"])
            try:
                proxy_client_sock.connect(serverAddress)
            except:
                print(f'Error connect to web server. Error: {e}')
                logging.error(f'Error connect to web server. Error: {e}')
                networklogger.info(f'{"TCP"},{str((time.perf_counter()-tcp_start_connection)*1000)},{str(len(req))},{tcpClientAddress[0]},{str(tcpClientAddress[1])},{"failed_web_server"},{url},{str(socket_timeout)}')
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
            tcp_end_connection = time.perf_counter()
        
        # Data logging
        if(clientSocket.gettimeout() != None):
            socket_timeout = clientSocket.gettimeout()
        else:
            socket_timeout = 0
        networklogger.info(f'{"TCP"},{str((tcp_end_connection-tcp_start_connection)*1000)},{str(len(req))},{tcpClientAddress[0]},{str(tcpClientAddress[1])},{"success"},{url},{str(socket_timeout)}')

        # Decrease client number
        self.clientNum = self.clientNum - 1
        
        # Connection forwarded successfully
        exit(0)
    
    def proxy_udp_thread(self, udpSocket, udpServerAddress, config):
        global networklogger
        udp_client_address = None
        r_bytes = None

        # Waiting for UDP connection
        while True:
            # Data receive
            data, address = udpSocket.recvfrom(config["UDP_BUFFERSIZE"])

            # Data forwarding (UDP multiclient)
            if address and data:
                if(udpSocket.gettimeout() != None):
                    socket_timeout = udpSocket.gettimeout()
                else:
                    socket_timeout = 0
                destination_addr = self.check_pairing(address, udpServerAddress, len(data), socket_timeout, config)
                if destination_addr != None:
                    udpSocket.sendto(data, destination_addr)
    
    def check_pairing(self, addr, udpServerAddress, data_bytes, socket_timeout, config):
        # Check if existing connection
        for i in range(len(self.udp_pair_list)):
            # If from client
            if addr == self.udp_pair_list[i][0]:
                # Add connection state (unbalanced connection)
                self.udp_pair_list[i][3] = self.udp_pair_list[i][3] + 1
                # Return server
                return self.udp_pair_list[i][1]
            
            # If from server
            if addr == self.udp_pair_list[i][1]:
                # return client address
                destination_addr = self.udp_pair_list[i][0]
                # logging
                networklogger.info(f'{"UDP"},{str((time.perf_counter() - self.udp_pair_list[i][2])*1000)},{str(self.udp_pair_list[i][4])},{self.udp_pair_list[i][0][0]},{str(self.udp_pair_list[i][0][1])},{str((self.udp_pair_list[i][3]-1))},{str(0)},{str(socket_timeout)}')
                # close connection
                self.udp_pair_list.pop(i)
                return destination_addr
        
        # new connection
        # if from server (must be already replied to client)
        if(addr == udpServerAddress):
            return None
        # if from client
        # client address, server address, initial time, initial connectionstate, initial connection size
        else:
            # print(["new pair"], [addr, udpServerAddress])
            self.udp_pair_list.append([addr, udpServerAddress, time.perf_counter(), 1, data_bytes])
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

def seedProxyConfiguration():
    global proxy_name
    
    configAll = {}
    count = 1
    try:
        file = open("ProxyConfig.json","r")
        data = json.load(file)
        file.close()

        if "proxyName" in data:
            if(isinstance(data["proxyName"], str)):
                proxy_name = data["proxyName"]
            else:
                print("Invalid proxyName")
        else:
            print("Missing proxyName")

        for i in data['proxyConfiguration']:
            config = {}
            # print(i)
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
            
            if("LIST_SERVER" in i):
                if(type(i["LIST_SERVER"])==list):
                    config["LIST_SERVER"] = i["LIST_SERVER"]
                else:
                    print("Invalid LIST_SERVER")
                    config["LIST_SERVER"] = []
            else:
                print("Missing LIST_SERVER")
                config["LIST_SERVER"] = []
            
            if("ENABLE_CACHE" in i):
                if(i["ENABLE_CACHE"]=="True" or i["ENABLE_CACHE"]=="False"):
                    config["ENABLE_CACHE"] = eval(i["ENABLE_CACHE"])
                else:
                    print("Invalid ENABLE_CACHE")
                    config["ENABLE_CACHE"] = False
            else:
                print("Missing ENABLE_CACHE")
                config["ENABLE_CACHE"] = False
            
            configAll["proxy{}".format(count)] = config
            count = count + 1
        return configAll

    except FileNotFoundError:
        print("Configuration Proxy (ProxyConfig.json) not found, setting default values")
        logging.warning("Configuration Proxy (ProxyConfig.json) not found, setting default values")
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
            "LIST_SERVER": ["127.0.0.1,5000", "127.0.0.1;5005"],
            "ENABLE_CACHE": False
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
    print(f"{proxy_name} is ready, creating proxy thread")
    for config_id, config in configAll.items():
        print("creating proxy: ", config_id)
        logging.debug(f"creating proxy: {config_id}")
        _proxy_server = Server(config)
        _proxy_server.start()
        proxy_servers.append(_proxy_server)

def restart_program():
    print("Restarting Program")
    logging.debug("Restarting Program")
    try:
        p = psutil.Process(os.getpid())
        for handler in p.get_open_files() + p.connections():
            os.close(handler.fd)
    except Exception as e:
        print(f"Programm cannot shutdown. Error: {e}")
        logging.error(f"Programm cannot shutdown. Error: {e}")
    python = sys.executable
    os.execl(python, python, *sys.argv)

def on_modified(event):
    print(f"{event.src_path} has been modified")
    logging.debug(f"{event.src_path} has been modified")
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
        self.data_count = 10

    def run(self):
        global http_model
        global http_scaller

        http_timeseries = {}

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
                ipaddresses = set(map(lambda x:x[5], raw_datas))
                protocols = set(map(lambda x:x[2], raw_datas))
                categoried_datas = [[[y for y in raw_datas if y[5]==x and y[2]==j] for x in ipaddresses]for j in protocols]

                # looping every each group (protocols x IP addresses)
                for protocol_data in categoried_datas:
                    if(len(protocol_data) != 0):
                        if(protocol_data[0][0][2] == "TCP"):
                            for ip_data in protocol_data:
                                if(len(ip_data) != 0):
                                    timestamp = []
                                    no_thread = []
                                    connection_time = []
                                    r_bytes = []
                                    port_src = []
                                    status = []
                                    url = []
                                    connection_timeout = []
                                    total_connection_sum = len(ip_data)
                                    for data in ip_data:
                                        if(len(data) != 0):
                                            if(data[0] != "NULL"):
                                                timestamp.append(float(data[0]))
                                            if(data[1] != "NULL"):
                                                no_thread.append(int(data[1]))
                                            if(data[3] != "NULL"):
                                                connection_time.append(float(data[3]))
                                            if(data[4] != "NULL"):
                                                r_bytes.append(int(data[4]))
                                            if(data[6] != "NULL"):
                                                port_src.append(int(data[6]))
                                            if(data[7] != "NULL"):
                                                status.append(self.StringToBytes(data[7]))
                                            if(data[8] != "NULL"):
                                                url.append(self.StringToBytes(data[8]))
                                            if(data[9] != "NULL"):
                                                connection_timeout.append(int(data[9]))
                                            http_timeseries_data = data.copy()
                                            http_timeseries_data.pop(0)
                                            http_timeseries_data.pop(1)
                                            http_timeseries_data.pop(3)
                                            http_timeseries_data[4] = self.StringToBytes(http_timeseries_data[4])
                                            http_timeseries_data[5] = self.StringToBytes(http_timeseries_data[5])
                                            http_timeseries_data.append("0")
                                            if data[5] in http_timeseries:
                                                http_timeseries[data[5]].append(http_timeseries_data)
                                            else:
                                                http_timeseries[data[5]] = []
                                                http_timeseries[data[5]].append(http_timeseries_data)
                                                                        
                                    timestamp_std = np.std(timestamp)
                                    no_thread_std = np.std(no_thread)
                                    connection_time_std = np.std(connection_time)
                                    r_bytes_std = np.std(r_bytes)
                                    r_bytes_sum = np.sum(r_bytes)
                                    port_src_std = np.std(port_src)
                                    status_std = np.std(status)
                                    url_std = np.std(url)
                                    connection_timeout_std = np.std(connection_timeout)
                                    rate_connection = total_connection_sum

                                    # Label : 0 Normal, 1 HTTP flood
                                    label = 0

                                    row = []
                                    row = [timestamp_std, no_thread_std, connection_time_std, r_bytes_std, r_bytes_sum, port_src_std, status_std, url_std, connection_timeout_std, rate_connection, label]
                                    
                                    with open('dataset_http_individual.csv', 'a') as datafile:
                                        writer = csv.writer(datafile, delimiter=",")
                                        writer.writerow(row)
                                    datafile.close()

                                    if ip_data[0][5] in http_timeseries:
                                        if(len(http_timeseries[ip_data[0][5]]) >= 51):
                                            with open('dataset_http_timeseries.csv', 'a') as f_object:
                                                writer_object = csv.writer(f_object)
                                                for data in http_timeseries[ip_data[0][5]]:
                                                    writer_object.writerow(data)
                                                f_object.close()
                                            http_timeseries[ip_data[0][5]] = []

            # Flush logfile
            with open(self.file_name, 'w'):
                pass

            # Flush data
            raw_datas = []

            # Sleep n second
            time.sleep(self.sleep_time)
    
    def StringToBytes(self, data):
        sum = 0
        arrbytes = bytes(data, 'utf-8')
        for i in arrbytes:
            sum = sum + i
        return(sum)

networklogger = None

proxy_servers = []

if __name__ == "__main__":
    #create a logger
    networklogger = logging.getLogger('networklogger')
    networklogger.setLevel(logging.INFO)
    networkloggerhandler = logging.FileHandler('network.log')
    networkloggerformatter = logging.Formatter('%(created)f,%(thread)d,%(message)s')
    networkloggerhandler.setFormatter(networkloggerformatter)
    #set filter to log only INFO lines
    networkloggerhandler.addFilter(LoggerFilter(logging.INFO))
    networklogger.addHandler(networkloggerhandler)

    # Initialize logging
    logging.basicConfig(filename='proxy_application.log', encoding='utf-8', level=logging.DEBUG,
                        format='%(created)f,%(thread)d,%(message)s')
    
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
        dataParser1 = DataParser()
        dataParser1.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()
