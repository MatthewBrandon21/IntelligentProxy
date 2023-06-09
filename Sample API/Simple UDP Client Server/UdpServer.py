import socket
import random
import string

localIP     = "127.0.0.1"
localPort   = 5005
bufferSize  = 1024

letters = string.ascii_letters

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and ip
UDPServerSocket.bind((localIP, localPort))

print("UDP server up and listening")

# Listen for incoming datagrams
while(True):
    # msgFromServer       = ''.join(random.choice(letters) for i in range(random.randint(0, 50)))
    msgFromServer       = 'Hi UDP Client'
    bytesToSend         = str.encode(msgFromServer)

    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    message = bytesAddressPair[0]
    address = bytesAddressPair[1]
    clientMsg = "Message from Client:{}".format(message)
    clientIP  = "Client IP Address:{}".format(address)
    print(clientMsg)
    print(clientIP)
    print(f"\nsize recieved: {len(bytesAddressPair[0])}")

    # Sending a reply to client
    UDPServerSocket.sendto(bytesToSend, address)