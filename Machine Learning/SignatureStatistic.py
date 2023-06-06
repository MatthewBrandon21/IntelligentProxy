import pandas as pd
from sklearn.cluster import KMeans
import numpy as np
from collections import Counter

tcp_signature = {
    "port_dest": 0,
    "dataofs": 0,
    "reserved": 0,
    "flags": "S",
    "window": 0,
    "urgptr": 0,
    "payload_len": 0
}


def StringToBytes(data):
    sum = 0
    arrbytes = bytes(data, 'utf-8')
    for i in arrbytes:
        sum = sum + i
    return(sum)

features, labels = [], []

def most_frequent(List):
    occurence_count = Counter(List)
    return occurence_count.most_common(1)[0][0]

meal = open("TestDatasetKmeans.csv", "rt")
for line in meal:
    data_list = line.rsplit(",")
    if(len(data_list) != 13):
        print("error data")
    else:
        data_list[(len(data_list)-1)]=data_list[(len(data_list)-1)].replace('\n', '')
        features.append(data_list[:(len(data_list)-1)])
        labels.append(data_list[(len(data_list)-1)])
meal.close()

bad_data = features[:200]
good_data = features[200:]

port_dest = []
dataofs = []
reserved = []
flags = []
window = []
urgptr = []
payload_len = []

print(len(bad_data))
print(len(good_data))

for data in bad_data:
    port_dest.append(int(data[2]))
    dataofs.append(int(data[5]))
    reserved.append(int(data[6]))
    flags.append(str(data[7]))
    window.append(int(data[8]))
    urgptr.append(int(data[10]))
    payload_len.append(int(data[11]))

tcp_signature['port_dest'] = most_frequent(port_dest)
tcp_signature['dataofs'] = most_frequent(dataofs)
tcp_signature['reserved'] = most_frequent(reserved)
tcp_signature['flags'] = most_frequent(flags)
tcp_signature['window'] = most_frequent(window)
tcp_signature['urgptr'] = most_frequent(urgptr)
tcp_signature['payload_len'] = most_frequent(payload_len)

print(tcp_signature)

sum = 1
for data in features:
    if(tcp_signature['port_dest'] == int(data[2]) and
       tcp_signature['dataofs'] == int(data[5]) and
       tcp_signature['reserved'] == int(data[6]) and
       tcp_signature['flags'] == str(data[7]) and
       tcp_signature['window'] == int(data[8]) and
       tcp_signature['urgptr'] == int(data[10]) and
       tcp_signature['payload_len'] == int(data[11])):
        sum = sum + 1

print(sum)