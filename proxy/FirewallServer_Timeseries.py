from netfilterqueue import NetfilterQueue
from scapy.all import *
import json
import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import logging
import threading
from threading import Thread
import numpy as np
import statistics
from statistics import mode

import joblib
from keras.models import load_model
from collections import Counter

from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

firewall_name = "node-firewall"

tcp_svm_instance = svm.SVC(kernel = 'linear', random_state=0)
tcp_scaler = StandardScaler()
udp_svm_instance = svm.SVC(kernel = 'linear', random_state=0)
udp_scaler = StandardScaler()
icmp_svm_instance = svm.SVC(kernel = 'linear', random_state=0)
icmp_scaler = StandardScaler()

tcp_lstm_scaler = joblib.load('./scaler/scaler_lstm_tcp.save')
tcp_lstm_model = load_model('./model/brnn_model_tcp.h5')
udp_lstm_scaler = joblib.load('./scaler/scaler_lstm_udp.save')
udp_lstm_model = load_model('./model/brnn_model_udp.h5')
icmp_lstm_scaler = joblib.load('./scaler/scaler_lstm_icmp.save')
icmp_lstm_model = load_model('./model/brnn_model_icmp.h5')

# Packet identification configuration
use_machine_learning_identifier = True

# Normal data
tcp_normal_data = []
udp_normal_data = []
icmp_normal_data = []

# Traffic Signature
tcp_signature = {
    "dataofs": 0,
    "reserved": 0,
    "flags": "S",
    "window": 0,
    "urgptr": 0,
    "payload_len": 0
}

udp_signature = {
    "len": 0,
    "payload_len": 0
}

icmp_signature = {
    "id": 0,
    "payload_len": 0
}

# DDoS status
tcp_ddos = False
udp_ddos = False
icmp_ddos = False

# Firewall config
ListOfBannedIpAddr = []
ListOfBannedPorts = []
ListOfBannedPrefixes = []
ListOfWebserverIpAddr = []
ListOfWebserverPorts = []

# Timeseries data
tcp_timeseries_data = []
udp_timeseries_data = []
icmp_timeseries_data = []

# Timeseries configuration
tcp_timeseries_len = 200
udp_timeseries_len = 200
icmp_timeseries_len = 200

# Seed from file function
def seedFromFile():
    global ListOfBannedIpAddr
    global ListOfBannedPorts
    global ListOfBannedPrefixes
    global firewall_name
    global ListOfWebserverIpAddr
    global ListOfWebserverPorts

    try:
        file = open("FirewallRules.json", "r")
        data = json.load(file)
        file.close()

        if "firewallName" in data:
            if(isinstance(data["firewallName"], str)):
                firewall_name = data["firewallName"]
            else:
                print("Invalid firewallName")
        else:
            print("Missing firewallName")

        # List of banned ip addresses
        if "ListOfBannedIpAddr" in data:
            if type(data["ListOfBannedIpAddr"]) == list:
                ListOfBannedIpAddr = data["ListOfBannedIpAddr"]
            else:
                ListOfBannedIpAddr = []
        else:
            ListOfBannedIpAddr = []
        
        # List of webserver ip addresses
        if "ListOfWebserverIpAddr" in data:
            if type(data["ListOfWebserverIpAddr"]) == list:
                ListOfWebserverIpAddr = data["ListOfWebserverIpAddr"]
            else:
                ListOfWebserverIpAddr = []
        else:
            ListOfWebserverIpAddr = []
        
        # List of webserver port
        if "ListOfWebserverPorts" in data:
            if type(data["ListOfWebserverPorts"]) == list:
                ListOfWebserverPorts = data["ListOfWebserverPorts"]
            else:
                ListOfWebserverPorts = []
        else:
            ListOfWebserverPorts = []

        # List of banned ports
        if "ListOfBannedPorts" in data:
            if type(data["ListOfBannedPorts"]) == list:
                ListOfBannedPorts = data["ListOfBannedPorts"]
            else:
                ListOfBannedPorts = []
        else:
            ListOfBannedPorts = []

        # List of banned prefixes, e.g. 172.x.x.x
        if "ListOfBannedPrefixes" in data:
            if type(data["ListOfBannedPrefixes"]) == list:
                ListOfBannedPrefixes = data["ListOfBannedPrefixes"]
            else:
                ListOfBannedPrefixes = []
        else:
            ListOfBannedPrefixes = []

    except FileNotFoundError:
        logging.info('Firewall rule (FirewallRules.json) not found, setting default values')
        ListOfBannedIpAddr = []
        ListOfWebserverIpAddr = []
        ListOfBannedPorts = []
        ListOfBannedPrefixes = []
        ListOfWebserverPorts = []

def firewall(pkt):
    global tcp_timeseries_data
    global udp_timeseries_data
    global icmp_timeseries_data
    global tcp_ddos
    global udp_ddos
    global icmp_ddos
    global tcp_svm_instance
    global tcp_scaler
    global udp_svm_instance
    global udp_scaler
    global icmp_svm_instance
    global icmp_scaler
    global use_machine_learning_identifier

    # parse packet data from incomming connection
    sca = IP(pkt.get_payload())

    # Webserver whitelist
    if sca.src in ListOfWebserverIpAddr:
        pkt.accept()
        return

    # IP address firewall
    if sca.src in ListOfBannedIpAddr:
        print(sca.src, "is a incoming IP address that is banned by the firewall.")
        logging.info(f'{sca.src} is a incoming IP address that is banned by the firewall.')
        pkt.drop()
        return

    # TCP Port firewall
    if sca.haslayer(TCP):
        t = sca.getlayer(TCP)
        if t.dport in ListOfBannedPorts:
            print(t.dport, "is a destination port that is blocked by the firewall.")
            logging.info(f'{t.dport} is a destination port that is blocked by the firewall.')
            pkt.drop()
            return

    # UDP Port firewall
    if sca.haslayer(UDP):
        t = sca.getlayer(UDP)
        if t.dport in ListOfBannedPorts:
            print(t.dport, "is a destination port that is blocked by the firewall.")
            logging.info(f'{t.dport} is a destination port that is blocked by the firewall.')
            pkt.drop()
            return

    # Prefixes firewall
    if True in [sca.src.find(suff) == 0 for suff in ListOfBannedPrefixes]:
        print("Prefix of " + sca.src + " is banned by the firewall.")
        logging.info(f'Prefix of {sca.src} is banned by the firewall.')
        pkt.drop()
        return
    
    if(sca.haslayer(TCP)):
        t = sca.getlayer(TCP)
        if t.dport in ListOfWebserverPorts:
            tcp_timeseries = [str(t.sport), str(t.seq), str(t.ack), str(t.dataofs), str(t.reserved), str(t.flags), str(t.window), str(t.chksum), str(t.urgptr), str(pkt.get_payload_len())]
            tcp_timeseries_data.append(tcp_timeseries)
            if(tcp_ddos):
                if(use_machine_learning_identifier):
                    tcp_prediction_time_start = time.perf_counter()
                    tcp_timeseries[5] = StringToBytes(tcp_timeseries[5])
                    tcp_data = tcp_scaler.transform([tcp_timeseries])
                    tcp_result = tcp_svm_instance.predict([tcp_data[0]])[0]
                    if(tcp_result == "1"):
                        pkt.drop()
                        print(f'TCP packet dropped, prediction time : {time.perf_counter() - tcp_prediction_time_start}')
                        return
                else:
                    if(tcp_comparator(pkt, t)):
                        print(f'TCP packet blocked, ip src : {sca.src}')
                        pkt.drop()
                        return
    
    if sca.haslayer(UDP):
        t = sca.getlayer(UDP)
        if t.dport in ListOfWebserverPorts:
            udp_timeseries = [str(t.sport), str(t.len), str(t.chksum), str(pkt.get_payload_len())]
            udp_timeseries_data.append(udp_timeseries)
            if(udp_ddos):
                if(use_machine_learning_identifier):
                    udp_prediction_time_start = time.perf_counter()
                    udp_data = udp_scaler.transform([udp_timeseries])
                    udp_result = udp_svm_instance.predict([udp_data[0]])[0]
                    if(udp_result == "1"):
                        pkt.drop()
                        print(f'UDP packet dropped, prediction time : {time.perf_counter() - udp_prediction_time_start}')
                        return
                else:
                    if(udp_comparator(pkt, t)):
                        print(f'UDP packet blocked, ip src : {sca.src}')
                        pkt.drop()
                        return
    
    if sca.haslayer(ICMP):
        t = sca.getlayer(ICMP)
        # Only ICMP echo request
        if(t.code==0 and t.type==8):
            icmp_timeseries = [str(t.chksum), str(t.id), str(t.seq), str(pkt.get_payload_len())]
            icmp_timeseries_data.append(icmp_timeseries)
            if(icmp_ddos):
                if(use_machine_learning_identifier):
                    icmp_prediction_time_start = time.perf_counter()
                    icmp_data = icmp_scaler.transform([icmp_timeseries])
                    icmp_result = icmp_svm_instance.predict([icmp_data[0]])[0]
                    if(icmp_result == "1"):
                        pkt.drop()
                        print(f'ICMP packet dropped, prediction time : {time.perf_counter() - icmp_prediction_time_start}')
                        return
                else:
                    if(icmp_comparator(pkt, t)):
                        print(f'ICMP packet blocked, ip src : {sca.src}')
                        pkt.drop()
                        return
    
    # Forward packet to iptables
    pkt.accept()

def StringToBytes( data):
    sum = 0
    arrbytes = bytes(data, 'utf-8')
    for i in arrbytes:
        sum = sum + i
    return(sum)

def tcp_comparator(pkt, t):
    global tcp_signature
    if(tcp_signature['dataofs'] == int(t.dataofs) and
       tcp_signature['reserved'] == int(t.reserved) and
       tcp_signature['flags'] == str(t.flags) and
       tcp_signature['window'] == int(t.window) and
       tcp_signature['urgptr'] == int(t.urgptr) and
       tcp_signature['payload_len'] == int(pkt.get_payload_len())):
        return True
    else:
        return False

def udp_comparator(pkt, t):
    global udp_signature
    if(udp_signature['len'] == int(t.len) and
       udp_signature['payload_len'] == int(pkt.get_payload_len())):
        return True
    else:
        return False

def icmp_comparator(pkt, t):
    global icmp_signature
    if(icmp_signature['id'] == int(t.id) and
       icmp_signature['payload_len'] == int(pkt.get_payload_len())):
        return True
    else:
        return False

# Handler if file configuration modified
def on_modified(event):
    print(f"{event.src_path} has been modified")
    logging.info(f'{event.src_path} has been modified')
    logging.info('Firewall listener updating file configuration...')
    seedFromFile()

# TCP Timeseries data prediction
class TimeseriesDataExporter_TCP(Thread):
    def __init__(self):
        super(TimeseriesDataExporter_TCP, self).__init__()

    def run(self):
        global tcp_timeseries_data
        global tcp_lstm_model
        global tcp_lstm_scaler
        global tcp_normal_data
        global tcp_svm_instance
        global tcp_scaler
        global tcp_ddos
        global tcp_timeseries_len
        global use_machine_learning_identifier

        while True:
            if(len(tcp_timeseries_data) >= (tcp_timeseries_len+1)):
                tcp_prediction_time_start = time.perf_counter()
                tcp_timeseries_data_temp = tcp_timeseries_data[:(tcp_timeseries_len+1)]

                for i in range(len(tcp_timeseries_data_temp)):
                    tcp_timeseries_data_temp[i][5] = self.StringToBytes(str(tcp_timeseries_data_temp[i][5]))
                
                tcp_timeseries_data_temp = tcp_lstm_scaler.transform(tcp_timeseries_data_temp)

                features = len(tcp_timeseries_data_temp[0])
                samples = tcp_timeseries_data_temp.shape[0]
                train_len = tcp_timeseries_len
                input_len = samples - train_len
                I = np.zeros((samples - train_len, train_len, features))

                for i in range(input_len):
                    temp = np.zeros((train_len, features))
                    for j in range(i, i + train_len - 1):
                        temp[j-i] = tcp_timeseries_data_temp[j]
                    I[i] = temp
                
                tcp_predict = tcp_lstm_model.predict(I[:tcp_timeseries_len], verbose=1)
                result = tcp_predict[0][0].round()
                print(f'TCP timeseries result : {result}, prediction time : {time.perf_counter() - tcp_prediction_time_start}')

                if(use_machine_learning_identifier):
                    if(result == 1.0 and len(tcp_normal_data) != 0):
                        # Creating Machine Learning Identifier
                        creating_machine_learning_start = time.perf_counter()
                        print("TCP Creating machine learning identifier")
                        
                        tcp_ddos = False

                        features, labels = [], []

                        tcp_bad_data = tcp_timeseries_data[:(tcp_timeseries_len+1)]

                        for i in range(len(tcp_bad_data)):
                            tcp_bad_data[i][5] = self.StringToBytes(str(tcp_bad_data[i][5]))
                            tcp_bad_data[i].append("1")
                        
                        tcp_svm_data = tcp_bad_data + tcp_normal_data

                        for data in tcp_svm_data:
                            features.append(data[:(len(data)-1)])
                            labels.append(data[(len(data)-1)])
                        print(f"Size of feature dataset : {len(features)}")
                        print(f"Size of feature dataset : {len(labels)}")  

                        features_train, features_test, labels_train, labels_test = train_test_split(features, labels, test_size = 0.20, stratify=labels, random_state = 0)
                        X_train = tcp_scaler.fit_transform(features_train)
                        X_test = tcp_scaler.transform(features_test)
                        tcp_svm_instance.fit(X_train, labels_train)
                        labels_pred = tcp_svm_instance.predict(X_test)
                        cm = confusion_matrix(labels_test,labels_pred)
                        print(f'confussion matrix : {cm}')
                        print(classification_report(labels_test,labels_pred))

                        tcp_ddos = True

                        print(f'TCP Finish creating machine learning identifier, creation time : {time.perf_counter() - creating_machine_learning_start}')
                        time.sleep(3)
                    elif(result != 1.0):
                        tcp_normal_data = tcp_timeseries_data[:(tcp_timeseries_len+1)]

                        for i in range(len(tcp_normal_data)):
                            tcp_normal_data[i][5] = self.StringToBytes(str(tcp_normal_data[i][5]))
                            tcp_normal_data[i].append("0")
                        
                        tcp_ddos = False
                    else:
                        print("TCP DDoS Mitigation skipped because tcp_normal_data is empty")
                else:
                    if(result == 1.0):
                        tcp_ddos = True

                        dataofs = []
                        reserved = []
                        flags = []
                        window = []
                        urgptr = []
                        payload_len = []

                        tcp_bad_data = tcp_timeseries_data[:(tcp_timeseries_len+1)]
                        for data in tcp_bad_data:
                            dataofs.append(data[3])
                            reserved.append(data[4])
                            flags.append(data[5])
                            window.append(data[6])
                            urgptr.append(data[8])
                            payload_len.append(data[9])
                        
                        tcp_signature['dataofs'] = self.most_frequent(dataofs)
                        tcp_signature['reserved'] = self.most_frequent(reserved)
                        tcp_signature['flags'] = self.most_frequent(flags)
                        tcp_signature['window'] = self.most_frequent(window)
                        tcp_signature['urgptr'] = self.most_frequent(urgptr)
                        tcp_signature['payload_len'] = self.most_frequent(payload_len)

                        print(f'Start blocking TCP DDoS packet, signature : {tcp_signature}')
                    else:
                        tcp_ddos = False
                
                tcp_timeseries_data_temp = []
                tcp_timeseries_data = []
    
    def StringToBytes(self, data):
        sum = 0
        arrbytes = bytes(data, 'utf-8')
        for i in arrbytes:
            sum = sum + i
        return(sum)
    
    def most_frequent(self, List):
        occurence_count = Counter(List)
        return occurence_count.most_common(1)[0][0]

# Timeseries data exporter
class TimeseriesDataExporter_UDP(Thread):
    def __init__(self):
        super(TimeseriesDataExporter_UDP, self).__init__()

    def run(self):
        global udp_timeseries_data
        global udp_lstm_model
        global udp_lstm_scaler
        global udp_normal_data
        global udp_svm_instance
        global udp_scaler
        global udp_ddos
        global udp_timeseries_len
        global use_machine_learning_identifier

        while True:
            if(len(udp_timeseries_data) >= (udp_timeseries_len+1)):
                udp_prediction_time_start = time.perf_counter()
                udp_timeseries_data_temp = udp_timeseries_data[:(udp_timeseries_len+1)]
                
                udp_timeseries_data_temp = udp_lstm_scaler.transform(udp_timeseries_data_temp)

                features = len(udp_timeseries_data_temp[0])
                samples = udp_timeseries_data_temp.shape[0]
                train_len = udp_timeseries_len
                input_len = samples - train_len
                I = np.zeros((samples - train_len, train_len, features))

                for i in range(input_len):
                    temp = np.zeros((train_len, features))
                    for j in range(i, i + train_len - 1):
                        temp[j-i] = udp_timeseries_data_temp[j]
                    I[i] = temp
                
                udp_predict = udp_lstm_model.predict(I[:udp_timeseries_len], verbose=1)
                result = udp_predict[0][0].round()
                print(f'UDP timeseries result : {result}, prediction time : {time.perf_counter() - udp_prediction_time_start}')

                if(use_machine_learning_identifier):
                    if(result == 1.0 and len(udp_normal_data) != 0):
                        # Creating Machine Learning Identifier
                        creating_machine_learning_start = time.perf_counter()
                        print("UDP Creating machine learning identifier")
                        
                        udp_ddos = False

                        features, labels = [], []

                        udp_bad_data = udp_timeseries_data[:(udp_timeseries_len+1)]

                        for i in range(len(udp_bad_data)):
                            udp_bad_data[i].append("1")
                        
                        udp_svm_data = udp_bad_data + udp_normal_data

                        for data in udp_svm_data:
                            features.append(data[:(len(data)-1)])
                            labels.append(data[(len(data)-1)])
                        print(f"Size of feature dataset : {len(features)}")
                        print(f"Size of feature dataset : {len(labels)}")  

                        features_train, features_test, labels_train, labels_test = train_test_split(features, labels, test_size = 0.20, stratify=labels, random_state = 0)
                        X_train = udp_scaler.fit_transform(features_train)
                        X_test = udp_scaler.transform(features_test)
                        udp_svm_instance.fit(X_train, labels_train)
                        labels_pred = udp_svm_instance.predict(X_test)
                        cm = confusion_matrix(labels_test,labels_pred)
                        print(f'confussion matrix : {cm}')
                        print(classification_report(labels_test,labels_pred))

                        udp_ddos = True

                        print(f'UDP Finish creating machine learning identifier, creation time : {time.perf_counter() - creating_machine_learning_start}')
                        time.sleep(3)
                    elif(result != 1.0):
                        udp_normal_data = udp_timeseries_data[:(udp_timeseries_len+1)]

                        for i in range(len(udp_normal_data)):
                            udp_normal_data[i].append("0")
                        
                        udp_ddos = False
                    else:
                        print("UDP DDoS Mitigation skipped because udp_normal_data is empty")
                else:
                    if(result == 1.0):
                        udp_ddos = True

                        packet_len = []
                        payload_len = []

                        udp_bad_data = udp_timeseries_data[:(udp_timeseries_len+1)]
                        for data in udp_bad_data:
                            packet_len.append(data[1])
                            payload_len.append(data[3])
                        
                        udp_signature['len'] = self.most_frequent(packet_len)
                        udp_signature['payload_len'] = self.most_frequent(payload_len)

                        print(f'Start blocking UDP DDoS packet, signature : {udp_signature}')
                    else:
                        udp_ddos = False
                
                udp_timeseries_data_temp = []
                udp_timeseries_data = []
    
    def most_frequent(self, List):
        occurence_count = Counter(List)
        return occurence_count.most_common(1)[0][0]

# Timeseries data exporter
class TimeseriesDataExporter_ICMP(Thread):
    def __init__(self):
        super(TimeseriesDataExporter_ICMP, self).__init__()

    def run(self):
        global icmp_timeseries_data
        global icmp_lstm_model
        global icmp_lstm_scaler
        global icmp_normal_data
        global icmp_svm_instance
        global icmp_scaler
        global icmp_ddos
        global icmp_timeseries_len
        global use_machine_learning_identifier

        while True:
            if(len(icmp_timeseries_data) >= (icmp_timeseries_len+1)):
                icmp_prediction_time_start = time.perf_counter()
                icmp_timeseries_data_temp = icmp_timeseries_data[:(icmp_timeseries_len+1)]
                
                icmp_timeseries_data_temp = icmp_lstm_scaler.transform(icmp_timeseries_data_temp)

                features = len(icmp_timeseries_data_temp[0])
                samples = icmp_timeseries_data_temp.shape[0]
                train_len = icmp_timeseries_len
                input_len = samples - train_len
                I = np.zeros((samples - train_len, train_len, features))

                for i in range(input_len):
                    temp = np.zeros((train_len, features))
                    for j in range(i, i + train_len - 1):
                        temp[j-i] = icmp_timeseries_data_temp[j]
                    I[i] = temp
                
                icmp_predict = icmp_lstm_model.predict(I[:icmp_timeseries_len], verbose=1)
                result = icmp_predict[0][0].round()
                print(f'ICMP timeseries result : {result}, prediction time : {time.perf_counter() - icmp_prediction_time_start}')

                if(use_machine_learning_identifier):
                    if(result == 1.0 and len(icmp_normal_data) != 0):
                        # Creating Machine Learning Identifier
                        creating_machine_learning_start = time.perf_counter()
                        print("ICMP Creating machine learning identifier")
                        
                        icmp_ddos = False

                        features, labels = [], []

                        icmp_bad_data = icmp_timeseries_data[:(icmp_timeseries_len+1)]

                        for i in range(len(icmp_bad_data)):
                            icmp_bad_data[i].append("1")
                        
                        icmp_svm_data = icmp_bad_data + icmp_normal_data

                        for data in icmp_svm_data:
                            features.append(data[:(len(data)-1)])
                            labels.append(data[(len(data)-1)])
                        print(f"Size of feature dataset : {len(features)}")
                        print(f"Size of feature dataset : {len(labels)}")  

                        features_train, features_test, labels_train, labels_test = train_test_split(features, labels, test_size = 0.20, stratify=labels, random_state = 0)
                        X_train = icmp_scaler.fit_transform(features_train)
                        X_test = icmp_scaler.transform(features_test)
                        icmp_svm_instance.fit(X_train, labels_train)
                        labels_pred = icmp_svm_instance.predict(X_test)
                        cm = confusion_matrix(labels_test,labels_pred)
                        print(f'confussion matrix : {cm}')
                        print(classification_report(labels_test,labels_pred))

                        icmp_ddos = True

                        print(f'ICMP Finish creating machine learning identifier, creation time : {time.perf_counter() - creating_machine_learning_start}')
                        time.sleep(3)
                    elif(result != 1.0):
                        icmp_normal_data = icmp_timeseries_data[:(icmp_timeseries_len+1)]

                        for i in range(len(icmp_normal_data)):
                            icmp_normal_data[i].append("0")
                        
                        icmp_ddos = False
                    else:
                        print("ICMP DDoS Mitigation skipped because icmp_normal_data is empty")
                else:
                    if(result == 1.0):
                        icmp_ddos = True

                        id = []
                        payload_len = []

                        icmp_bad_data = icmp_timeseries_data[:(icmp_timeseries_len+1)]
                        for data in icmp_bad_data:
                            id.append(data[1])
                            payload_len.append(data[3])
                        
                        icmp_signature['id'] = self.most_frequent(id)
                        icmp_signature['payload_len'] = self.most_frequent(payload_len)

                        print(f'Start blocking ICMP DDoS packet, signature : {icmp_signature}')
                    else:
                        icmp_ddos = False
                
                icmp_timeseries_data_temp = []
                icmp_timeseries_data = []
    
    def most_frequent(self, List):
        occurence_count = Counter(List)
        return occurence_count.most_common(1)[0][0]

class LoggerFilter(object):
    def __init__(self, level):
        self.__level = level
    def filter(self, logRecord):
        return logRecord.levelno == self.__level

if __name__ == "__main__":
    # Logging initialization
    logging.basicConfig(filename='firewall_application.log', encoding='utf-8', level=logging.DEBUG,
                        format='%(created)f,%(message)s')

    # Watchdog initialization
    patterns = ["*"]
    ignore_patterns = None
    ignore_directories = False
    case_sensitive = True
    my_event_handler = PatternMatchingEventHandler(
        patterns, ignore_patterns, ignore_directories, case_sensitive
    )
    my_event_handler.on_modified = on_modified
    path = "FirewallRules.json"
    go_recursively = True
    my_observer = Observer()
    my_observer.schedule(my_event_handler, path, recursive=go_recursively)
    my_observer.start()

    # nfqueue initialization
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, firewall)
    try:
        seedFromFile()
        print(f"{firewall_name} is ready, creating traffic listener")
        dataExporter1 = TimeseriesDataExporter_TCP()
        dataExporter1.start()
        dataExporter2 = TimeseriesDataExporter_UDP()
        dataExporter2.start()
        dataExporter3 = TimeseriesDataExporter_ICMP()
        dataExporter3.start()
        nfqueue.run()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()
        nfqueue.unbind()