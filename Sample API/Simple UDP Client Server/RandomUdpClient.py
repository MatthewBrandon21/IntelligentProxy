import socket
from sys import argv
import sys
import platform
import threading
import time
import random
import string

letters = string.ascii_letters
system = platform.uname()[0]
End = '\033[0m'
help_command = """
Random Request Generator:
            python .\RandomUdpClient.py 192.168.29.128 3002 20 10
          --help
"""

def main():
    if argv[1] == argv[1]:
        try:
            serverAddressPort   = (argv[1], int(argv[2]))
            bufferSize          = 1024
            time_input = int(argv[3])
            thread_count = int(argv[4])
            t_end = time.time() + time_input
            time.sleep(0.35)
            print("\nUsage: Ctrl + C To Exit!!!\n")
            def run(h):
                UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
                while time.time() < t_end:
                    try:
                        # msgFromClient       = ''.join(random.choice(letters) for i in range(random.randint(0, 50)))
                        msgFromClient       = 'HI UDP SERVER'
                        bytesToSend         = str.encode(msgFromClient)
                        start_time = time.perf_counter()
                        # Send to server using created UDP socket
                        UDPClientSocket.sendto(bytesToSend, serverAddressPort)
                        msgFromServer = UDPClientSocket.recvfrom(bufferSize)
                        print(f"\nPacket send to {serverAddressPort}, response time: {(time.perf_counter()-start_time)*1000} ms, size response: {len(msgFromServer[0])}")
                        msg = "Message from Server {}".format(msgFromServer[0])
                        print(msg)
                    except Exception as e:
                        print(f"Send packet error, error : {e}")
                    
                    # Random sleep time from 0 to 10 seconds
                    time.sleep(random.randint(0, 10))
            for i in range(thread_count):
                t = threading.Thread(target=run, args=[i])
                t.start()
        except KeyboardInterrupt:
            print("\nCtrl + C")
            print("\nStop " + "Generating !!!\n" + End)
            sys.exit()
    elif argv[1] == '--help':
        print(help_command)
        sys.exit()
    else:
        print("{} Not Found!".format(argv[1]))
        sys.exit()
if __name__ == '__main__':
    try:
        main()
    except IndexError:
        print(help_command)