import select
import socket
import sys
import queue

PROXY_HOST = '0.0.0.0'
PROXY_PORT = 3001
NUMBER_OF_CONNECTION = 5

# TCP SETUP
proxy_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# prevents port already used of other thread
proxy_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
proxy_tcp.setblocking(0)
proxy_tcp.bind((PROXY_HOST, PROXY_PORT))
proxy_tcp.listen(NUMBER_OF_CONNECTION)

# UDP SETUP
proxy_udp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
proxy_udp.bind((PROXY_HOST,PROXY_PORT))

input_connections = [proxy_udp,proxy_tcp]
output_connections = []
message_queues = {}

while input_connections:
    incoming, outcoming, input_exception = select.select(input_connections, output_connections, input_connections)

    # data incoming
    for socket in incoming:
        # TCP incoming
        if socket is proxy_tcp:
            # create TCP queues
            connection, client_address = socket.accept()
            connection.setblocking(0)
            input_connections.append(connection)
            print("Received connection request from: ",client_address)
            message_queues[connection] = queue.Queue()
        
        # UDP incoming
        elif socket is proxy_udp:
            data, addr = socket.recvfrom(1024)
            if data:
                print("data received over UDP: ", data)
                # reply connection
                data = ("ACK - data received: "+str(data)).encode()
                socket.sendto(data,addr)
        
        # do TCP packet queues
        else:
            data = socket.recv(1024)
            if data:
                print("data received: ",data)
                # reply connection
                data = ("ACK - data received: "+str(data)).encode()
                message_queues[socket].put(data)
                # queue the reply connection
                if socket not in output_connections:
                    output_connections.append(socket)
    
    # data outcoming
    for socket in outcoming:
        if not message_queues[socket].empty():
            next_msg = message_queues[socket].get()
            socket.send(next_msg)
        else:
            # Empty packet
            output_connections.remove(socket)
    
    # throw exception
    for socket in input_exception:
        input_connections.remove(socket)
        if socket in output_connections:
            output_connections.remove(socket)
        socket.close()
        del message_queues[socket]