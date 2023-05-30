import requests
from sys import argv
import sys
import platform
import threading
import time
import random
import json

system = platform.uname()[0]
End = '\033[0m'
help_command = """
Random Request Generator:
          ./RandomRequestGenerator.py <Time (s)> <threadCount>
          --help
"""

def main():
    if argv[1] == argv[1]:
        try:
            time_input = int(argv[1])
            thread_count = int(argv[2])
            t_end = time.time() + time_input
            time.sleep(0.35)
            print("\nUsage: Ctrl + C To Exit!!!\n")
            def run(h):
                global allEndpoints
                while time.time() < t_end:
                    try:
                        x = random.randint(1, len(allEndpoints))
                        url_request = "http://192.168.29.128:3001/"
                        start_time = time.perf_counter()
                        if(allEndpoints[x]["type"] == "GET"):
                            response = requests.get(url_request, timeout=2.50)
                        else:
                            response = requests.post(url_request, json=allEndpoints[x]["obj"], timeout=2.50, stream=True)
                        print(f"\nPacket send to {url_request}, response time: {(time.perf_counter()-start_time)*1000} ms")
                        print(response.content)
                    except Exception as e:
                        print(f"Send packet error, error : {e}")
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