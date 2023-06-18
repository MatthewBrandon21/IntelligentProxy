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

try:
    allEndpoints = {}
    endpoint_count = 1
    file = open("EndpointsSnort.json","r")
    data_raw = json.load(file)
    file.close()
    for i in data_raw['endpoints']:
        endpoints = {}
        if("type" in i):
            if(isinstance(i["type"], str)):
                endpoints["type"] = i["type"]
            else:
                print("Invalid type")
                endpoints["type"] = "GET"
        else:
            print("Missing type")
            endpoints["type"] = "GET"
        
        if("protocol" in i):
            if(isinstance(i["protocol"], str)):
                endpoints["protocol"] = i["protocol"]
            else:
                print("Invalid protocol")
                endpoints["protocol"] = "http"
        else:
            print("Missing protocol")
            endpoints["protocol"] = "http"
        
        if("ip" in i):
            if(isinstance(i["ip"], str)):
                endpoints["ip"] = i["ip"]
            else:
                print("Invalid ip")
                endpoints["ip"] = "192.168.29.128"
        else:
            print("Missing ip")
            endpoints["ip"] = "192.168.29.128"
        
        if("port" in i):
            if(type(i["port"])==int):
                endpoints["port"] = i["port"]
            else:
                print("Invalid port")
                endpoints["port"] = 3001
        else:
            print("Missing port")
            endpoints["port"] = 3001
        
        if("url" in i):
            if(isinstance(i["url"], str)):
                endpoints["url"] = i["url"]
            else:
                print("Invalid url")
                endpoints["url"] = "/"
        else:
            print("Missing url")
            endpoints["url"] = "/"
        
        if("obj" in i):
            endpoints["obj"] = i["obj"]
        else:
            endpoints["obj"] = {}
        
        allEndpoints[endpoint_count] = endpoints
        endpoint_count = endpoint_count + 1

except FileNotFoundError:
    print("Endpoints.json file not found!")

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
                        url_request = allEndpoints[x]["protocol"] + "://" + allEndpoints[x]["ip"] + ":" + str(allEndpoints[x]["port"])+ allEndpoints[x]["url"]
                        start_time = time.perf_counter()
                        if(allEndpoints[x]["type"] == "GET"):
                            response = requests.get(url_request, timeout=2.50)
                        else:
                            response = requests.post(url_request, json=allEndpoints[x]["obj"], timeout=2.50, stream=True)
                        print(f"\nPacket send to {url_request}, response time: {(time.perf_counter()-start_time)*1000} ms")
                        print(response.content)
                    except Exception as e:
                        print(f"Send packet error, error : {e}")
                    
                    # Random sleep time from 0 to 60 seconds
                    time.sleep(random.randint(0, 60))
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