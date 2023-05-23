import requests
import time
import random
import json

try:
    allEndpoints = {}
    endpoint_count = 1
    file = open("Endpoints.json","r")
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

print(allEndpoints)
url = allEndpoints[3]["protocol"] + "://" + allEndpoints[3]["ip"] + ":" + str(allEndpoints[3]["port"])+ allEndpoints[3]["url"]
print(url)

myobj = {'data': 'dataku'}
# response = requests.get(url)
response = requests.post(url, json=myobj, timeout=2.50, stream=True)
print(response.content)