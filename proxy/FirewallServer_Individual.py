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
from collections import Counter

import joblib

from sklearn import svm
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

firewall_name = "node-firewall"

# Packet identification configuration
use_machine_learning_identifier = True

tcp_svm_instance = svm.SVC(kernel = 'linear', random_state=0)
tcp_scaler = StandardScaler()
udp_svm_instance = svm.SVC(kernel = 'linear', random_state=0)
udp_scaler = StandardScaler()
icmp_nb_instance = GaussianNB()
icmp_scaler = StandardScaler()

tcp_svm_model = joblib.load('./model/tcp_svm.sav')
tcp_svm_scaller = joblib.load('./scaler/tcp_svm.save')
udp_knn_model = joblib.load('./model/udp_knn.sav')
udp_knn_scaller = joblib.load('./scaler/udp_knn.save')
icmp_lr_model = joblib.load('./model/icmp_lr.sav')
icmp_lr_scaller = joblib.load('./scaler/icmp_lr.save')

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

# logging data
tcp_file_name = "tcp_firewall_network.log"
udp_file_name = "udp_firewall_network.log"
icmp_file_name = "icmp_firewall_network.log"

# logger
tcp_networklogger = None
udp_networklogger = None
icmp_networklogger = None

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
    global tcp_networklogger
    global udp_networklogger
    global icmp_networklogger
    global tcp_ddos
    global udp_ddos
    global icmp_ddos
    global tcp_svm_instance
    global tcp_scaler
    global udp_svm_instance
    global udp_scaler
    global icmp_nb_instance
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
            tcp_networklogger.info(f'{sca.src},{str(t.sport)},{str(t.seq)},{str(t.ack)},{str(t.dataofs)},{str(t.reserved)},{str(t.flags)},{str(t.window)},{str(t.chksum)},{str(t.urgptr)},{str(pkt.get_payload_len())}')
            tcp_identifier = [str(t.sport), str(t.seq), str(t.ack), str(t.dataofs), str(t.reserved), str(t.flags), str(t.window), str(t.chksum), str(t.urgptr), str(pkt.get_payload_len())]
            if(tcp_ddos):
                if(use_machine_learning_identifier):
                    tcp_prediction_time_start = time.perf_counter()
                    tcp_identifier[5] = StringToBytes(tcp_identifier[5])
                    tcp_data = tcp_scaler.transform([tcp_identifier])
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
            udp_networklogger.info(f'{sca.src},{str(t.sport)},{str(t.len)},{str(t.chksum)},{str(pkt.get_payload_len())}')
            udp_identifier = [str(t.sport), str(t.len), str(t.chksum), str(pkt.get_payload_len())]
            if(udp_ddos):
                if(use_machine_learning_identifier):
                    udp_prediction_time_start = time.perf_counter()
                    udp_data = udp_scaler.transform([udp_identifier])
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
            icmp_networklogger.info(f'{sca.src},{str(t.chksum)},{str(t.id)},{str(t.seq)},{str(pkt.get_payload_len())}')
            icmp_identifier = [str(t.chksum), str(t.id), str(t.seq), str(pkt.get_payload_len())]
            if(icmp_ddos):
                if(use_machine_learning_identifier):
                    icmp_prediction_time_start = time.perf_counter()
                    icmp_data = icmp_scaler.transform([icmp_identifier])
                    icmp_result = icmp_nb_instance.predict([icmp_data[0]])[0]
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

# TCP Data prediction (will check every n second)
class DataParser_TCP(Thread):
    def __init__(self):
        super(DataParser_TCP, self).__init__()

        # Data parser configuration
        self.sleep_time = 5
        self.tcp_data_count = 12

    def run(self):
        global tcp_file_name
        global tcp_svm_model
        global tcp_svm_scaller
        global tcp_ddos
        global tcp_svm_instance
        global tcp_scaler
        global tcp_normal_data

        while True:
            # Array for save raw data from file
            tcp_raw_datas = []

            # Read and parse tcp logfile
            tcp_network_log_file = open(tcp_file_name, 'r')
            tcp_network_lines = tcp_network_log_file.readlines()
            if(len(tcp_network_lines) != 0):
                tcp_flow_prediction_time_start = time.perf_counter()

                for line in tcp_network_lines:
                    text = line.strip()
                    data = text.split(",")

                    # Check if data count is correct
                    if(len(data) == self.tcp_data_count):
                        tcp_raw_datas.append(data)
                    else:
                        print("Data parser TCP input format wrong")
                        logging.debug("Data parser TCP input format wrong")

                timestamp = []
                ip_src = []
                port_src = []
                seq = []
                ack = []
                dataofs = []
                reserved = []
                flags = []
                raw_flags = []
                window = []
                chksum = []
                urgptr = []
                payload_len = []

                total_connection_sum = len(tcp_raw_datas)
                for data in tcp_raw_datas:
                    if(data[0] != "NULL"):
                        timestamp.append(float(data[0]))
                    if(data[1] != "NULL"):
                        ip_src.append(self.StringToBytes(data[1]))
                    if(data[2] != "NULL"):
                        port_src.append(int(data[2]))
                    if(data[3] != "NULL"):
                        seq.append(int(data[3]))
                    if(data[4] != "NULL"):
                        ack.append(int(data[4]))
                    if(data[5] != "NULL"):
                        dataofs.append(int(data[5]))
                    if(data[6] != "NULL"):
                        reserved.append(int(data[6]))
                    if(data[7] != "NULL"):
                        flags.append(self.StringToBytes(data[7]))
                        raw_flags.append(str(data[7]))
                    if(data[8] != "NULL"):
                        window.append(int(data[8]))
                    if(data[9] != "NULL"):
                        chksum.append(int(data[9]))
                    if(data[10] != "NULL"):
                        urgptr.append(int(data[10]))
                    if(data[11] != "NULL"):
                        payload_len.append(int(data[11]))
                
                timestamp_std = np.std(timestamp)
                ip_src_std = np.std(ip_src)
                port_src_std = np.std(port_src)
                seq_std = np.std(seq)
                ack_std = np.std(ack)
                dataofs_std = np.std(dataofs)
                reserved_std = np.std(reserved)
                flags_std = np.std(flags)
                window_std = np.std(window)
                chksum_std = np.std(chksum)
                urgptr_std = np.std(urgptr)
                payload_len_std = np.std(payload_len)
                rate_connection = total_connection_sum

                tcp_input = [timestamp_std,ip_src_std,port_src_std,seq_std,ack_std,dataofs_std,reserved_std,flags_std,window_std,chksum_std,urgptr_std,payload_len_std,rate_connection]

                tcp_scaled_input_data = tcp_svm_scaller.transform([tcp_input])
                tcp_result = tcp_svm_model.predict([tcp_scaled_input_data[0]])[0]

                print(f"Predicted TCP flow result : {tcp_result}, with prediction time : {time.perf_counter() - tcp_flow_prediction_time_start}")

                if(use_machine_learning_identifier):
                    if(tcp_result == "1" and len(tcp_normal_data) != 0):
                        if(tcp_ddos == False):
                            # Creating Machine Learning Identifier
                            creating_machine_learning_start = time.perf_counter()
                            print("TCP Creating machine learning identifier")
                            
                            features, labels = [], []

                            tcp_bad_data = tcp_normal_data = tcp_raw_datas

                            for i in range(len(tcp_bad_data)):
                                tcp_bad_data[i].pop(0) #timestamp
                                tcp_bad_data[i].pop(0) #ipaddress
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
                    elif(tcp_result != "1"):
                        tcp_normal_data = tcp_raw_datas

                        for i in range(len(tcp_normal_data)):
                            tcp_normal_data[i].pop(0) #timestamp
                            tcp_normal_data[i].pop(0) #ipaddress
                            tcp_normal_data[i][5] = self.StringToBytes(str(tcp_normal_data[i][5]))
                            tcp_normal_data[i].append("0")
                        
                        tcp_ddos = False
                    else:
                        print("TCP DDoS Mitigation skipped because tcp_normal_data is empty")
                else:
                    if(tcp_result == "1"):
                        tcp_ddos = True
                        tcp_signature['dataofs'] = self.most_frequent(dataofs)
                        tcp_signature['reserved'] = self.most_frequent(reserved)
                        tcp_signature['flags'] = self.most_frequent(raw_flags)
                        tcp_signature['window'] = self.most_frequent(window)
                        tcp_signature['urgptr'] = self.most_frequent(urgptr)
                        tcp_signature['payload_len'] = self.most_frequent(payload_len)
                        print(f'Start blocking TCP DDoS packet, signature : {tcp_signature}')
                    else:
                        tcp_ddos = False
            
            # Flush logfiles
            with open(tcp_file_name, 'w'):
                pass

            # Flush data
            tcp_raw_datas = []

            # Sleep n second
            time.sleep(self.sleep_time)
    
    def most_frequent(self, List):
        occurence_count = Counter(List)
        return occurence_count.most_common(1)[0][0]

    def StringToBytes(self, data):
        sum = 0
        arrbytes = bytes(data, 'utf-8')
        for i in arrbytes:
            sum = sum + i
        return(sum)

# UDP Data prediction (will check every n second)
class DataParser_UDP(Thread):
    def __init__(self):
        super(DataParser_UDP, self).__init__()

        # Data parser configuration
        self.sleep_time = 5
        self.udp_data_count = 6

    def run(self):
        global udp_file_name
        global udp_knn_model
        global udp_knn_scaller
        global udp_ddos
        global udp_svm_instance
        global udp_scaler
        global udp_normal_data

        while True:
            # Array for save raw data from file
            udp_raw_datas = []
            
            # Read and parse udp logfile
            udp_network_log_file = open(udp_file_name, 'r')
            udp_network_lines = udp_network_log_file.readlines()
            if(len(udp_network_lines) != 0):
                udp_flow_prediction_time_start = time.perf_counter()
                for line in udp_network_lines:
                    text = line.strip()
                    data = text.split(",")

                    # Check if data count is correct
                    if(len(data) == self.udp_data_count):
                        udp_raw_datas.append(data)
                    else:
                        print("Data parser UDP input format wrong")
                        logging.debug("Data parser UDP input format wrong")

                timestamp = []
                ip_src = []
                port_src = []
                len_pkt = []
                chksum = []
                payload_len = []
                total_connection_sum = len(udp_raw_datas)

                for data in udp_raw_datas:
                    if(data[0] != "NULL"):
                        timestamp.append(float(data[0]))
                    if(data[1] != "NULL"):
                        ip_src.append(self.StringToBytes(data[1]))
                    if(data[2] != "NULL"):
                        port_src.append(int(data[2]))
                    if(data[3] != "NULL"):
                        len_pkt.append(int(data[3]))
                    if(data[4] != "NULL"):
                        chksum.append(int(data[4]))
                    if(data[5] != "NULL"):
                        payload_len.append(int(data[5]))
                
                timestamp_std = np.std(timestamp)
                ip_src_std = np.std(ip_src)
                port_src_std = np.std(port_src)
                len_std = np.std(len_pkt)
                chksum_std = np.std(chksum)
                payload_len_std = np.std(payload_len)
                rate_connection = total_connection_sum

                udp_input = [timestamp_std,ip_src_std,port_src_std,len_std,chksum_std,payload_len_std,rate_connection]

                udp_scaled_input_data = udp_knn_scaller.transform([udp_input])
                udp_result = udp_knn_model.predict([udp_scaled_input_data[0]])[0]

                print(f"Predicted UDP flow result : {udp_result}, with prediction time : {time.perf_counter() - udp_flow_prediction_time_start}")
                if(use_machine_learning_identifier):
                    if(udp_result == "1" and len(udp_normal_data) != 0):
                        if(udp_ddos == False):
                            # Creating Machine Learning Identifier
                            creating_machine_learning_start = time.perf_counter()
                            print("UDP Creating machine learning identifier")
                            
                            features, labels = [], []

                            udp_bad_data = udp_normal_data = udp_raw_datas

                            for i in range(len(udp_bad_data)):
                                udp_bad_data[i].pop(0) #timestamp
                                udp_bad_data[i].pop(0) #ipaddress
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
                    elif(udp_result != "1"):
                        udp_normal_data = udp_raw_datas

                        for i in range(len(udp_normal_data)):
                            udp_normal_data[i].pop(0) #timestamp
                            udp_normal_data[i].pop(0) #ipaddress
                            udp_normal_data[i].append("0")
                        
                        udp_ddos = False
                    else:
                        print("UDP DDoS Mitigation skipped because udp_normal_data is empty")
                else:
                    if(udp_result == "1"):
                        udp_ddos = True
                        udp_signature['len'] = self.most_frequent(len_pkt)
                        udp_signature['payload_len'] = self.most_frequent(payload_len)
                        print(f'Start blocking UDP DDoS packet, signature : {udp_signature}')
                    else:
                        udp_ddos = False
            
            # Flush logfiles
            with open(udp_file_name, 'w'):
                pass

            # Flush data
            udp_raw_datas = []

            # Sleep n second
            time.sleep(self.sleep_time)
    
    def most_frequent(self, List):
        occurence_count = Counter(List)
        return occurence_count.most_common(1)[0][0]

    def StringToBytes(self, data):
        sum = 0
        arrbytes = bytes(data, 'utf-8')
        for i in arrbytes:
            sum = sum + i
        return(sum)

# ICMP Data prediction (will check every n second)
class DataParser_ICMP(Thread):
    def __init__(self):
        super(DataParser_ICMP, self).__init__()

        # Data parser configuration
        self.sleep_time = 5
        self.icmp_data_count = 6

    def run(self):
        global icmp_file_name
        global icmp_lr_model
        global icmp_lr_scaller
        global icmp_ddos
        global icmp_nb_instance
        global icmp_scaler
        global icmp_normal_data

        while True:
            # Array for save raw data from file
            icmp_raw_datas = []
            
            # Read and parse icmp logfile
            icmp_network_log_file = open(icmp_file_name, 'r')
            icmp_network_lines = icmp_network_log_file.readlines()
            if(len(icmp_network_lines) != 0):
                icmp_flow_prediction_time_start = time.perf_counter()
                for line in icmp_network_lines:
                    text = line.strip()
                    data = text.split(",")

                    # Check if data count is correct
                    if(len(data) == self.icmp_data_count):
                        icmp_raw_datas.append(data)
                    else:
                        print("Data parser ICMP input format wrong")
                        logging.debug("Data parser ICMP input format wrong")

                timestamp = []
                ip_src = []
                chksum = []
                id = []
                seq = []
                payload_len = []
                total_connection_sum = len(icmp_raw_datas)

                for data in icmp_raw_datas:
                    if(data[0] != "NULL"):
                        timestamp.append(float(data[0]))
                    if(data[1] != "NULL"):
                        ip_src.append(self.StringToBytes(data[1]))
                    if(data[2] != "NULL"):
                        chksum.append(int(data[2]))
                    if(data[3] != "NULL"):
                        id.append(int(data[3]))
                    if(data[4] != "NULL"):
                        seq.append(int(data[4]))
                    if(data[5] != "NULL"):
                        payload_len.append(int(data[5]))
                
                timestamp_std = np.std(timestamp)
                ip_src_std = np.std(ip_src)
                chksum_std = np.std(chksum)
                id_std = np.std(id)
                seq_std = np.std(seq)
                payload_len_std = np.std(payload_len)
                rate_connection = total_connection_sum

                icmp_input = [timestamp_std,ip_src_std,chksum_std,id_std,seq_std,payload_len_std,rate_connection]

                icmp_scaled_input_data = icmp_lr_scaller.transform([icmp_input])
                icmp_result = icmp_lr_model.predict([icmp_scaled_input_data[0]])[0]
                print(f"Predicted ICMP flow result : {icmp_result}, with prediction time : {time.perf_counter() - icmp_flow_prediction_time_start}")
                if(use_machine_learning_identifier):
                    if(icmp_result == "1" and len(icmp_normal_data) != 0):
                        if(icmp_ddos == False):
                            # Creating Machine Learning Identifier
                            creating_machine_learning_start = time.perf_counter()
                            print("ICMP Creating machine learning identifier")
                            
                            features, labels = [], []

                            icmp_bad_data = icmp_normal_data = icmp_raw_datas

                            for i in range(len(icmp_bad_data)):
                                icmp_bad_data[i].pop(0) #timestamp
                                icmp_bad_data[i].pop(0) #ipaddress
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
                            icmp_nb_instance.fit(X_train, labels_train)
                            labels_pred = icmp_nb_instance.predict(X_test)
                            cm = confusion_matrix(labels_test,labels_pred)
                            print(f'confussion matrix : {cm}')
                            print(classification_report(labels_test,labels_pred))

                            icmp_ddos = True

                            print(f'ICMP Finish creating machine learning identifier, creation time : {time.perf_counter() - creating_machine_learning_start}')
                            time.sleep(3)
                    elif(icmp_result != "1"):
                        icmp_normal_data = icmp_raw_datas

                        for i in range(len(icmp_normal_data)):
                            icmp_normal_data[i].pop(0) #timestamp
                            icmp_normal_data[i].pop(0) #ipaddress
                            icmp_normal_data[i].append("0")
                        
                        icmp_ddos = False
                    else:
                        print("ICMP DDoS Mitigation skipped because icmp_normal_data is empty")
                else:
                    if(icmp_result == "1"):
                        icmp_ddos = True
                        icmp_signature['id'] = self.most_frequent(id)
                        icmp_signature['payload_len'] = self.most_frequent(payload_len)
                        print(f'Start blocking ICMP DDoS packet, signature : {icmp_signature}')
                    else:
                        icmp_ddos = False
            
            # Flush logfiles
            with open(icmp_file_name, 'w'):
                pass

            # Flush data
            icmp_raw_datas = []

            # Sleep n second
            time.sleep(self.sleep_time)
    
    def most_frequent(self, List):
        occurence_count = Counter(List)
        return occurence_count.most_common(1)[0][0]

    def StringToBytes(self, data):
        sum = 0
        arrbytes = bytes(data, 'utf-8')
        for i in arrbytes:
            sum = sum + i
        return(sum)

class LoggerFilter(object):
    def __init__(self, level):
        self.__level = level
    def filter(self, logRecord):
        return logRecord.levelno == self.__level

if __name__ == "__main__":
    #create a TCP logger
    tcp_networklogger = logging.getLogger('tcp_networklogger')
    tcp_networklogger.setLevel(logging.INFO)
    tcp_networkloggerhandler = logging.FileHandler(tcp_file_name)
    tcp_networkloggerformatter = logging.Formatter('%(created)f,%(message)s')
    tcp_networkloggerhandler.setFormatter(tcp_networkloggerformatter)
    #set filter to log only INFO lines
    tcp_networkloggerhandler.addFilter(LoggerFilter(logging.INFO))
    tcp_networklogger.addHandler(tcp_networkloggerhandler)

    #create a UDP logger
    udp_networklogger = logging.getLogger('udp_networklogger')
    udp_networklogger.setLevel(logging.INFO)
    udp_networkloggerhandler = logging.FileHandler(udp_file_name)
    udp_networkloggerformatter = logging.Formatter('%(created)f,%(message)s')
    udp_networkloggerhandler.setFormatter(udp_networkloggerformatter)
    #set filter to log only INFO lines
    udp_networkloggerhandler.addFilter(LoggerFilter(logging.INFO))
    udp_networklogger.addHandler(udp_networkloggerhandler)

    #create a ICMP logger
    icmp_networklogger = logging.getLogger('icmp_networklogger')
    icmp_networklogger.setLevel(logging.INFO)
    icmp_networkloggerhandler = logging.FileHandler(icmp_file_name)
    icmp_networkloggerformatter = logging.Formatter('%(created)f,%(message)s')
    icmp_networkloggerhandler.setFormatter(icmp_networkloggerformatter)
    #set filter to log only INFO lines
    icmp_networkloggerhandler.addFilter(LoggerFilter(logging.INFO))
    icmp_networklogger.addHandler(icmp_networkloggerhandler)

    # Logging initialization
    logging.basicConfig(filename='firewall_application.log', encoding='utf-8', level=logging.DEBUG,
                        format='%(created)f,%(message)s')
    
    # Make sure logging file is empty
    with open(tcp_file_name, 'w'):
        pass
    with open(udp_file_name, 'w'):
        pass
    with open(icmp_file_name, 'w'):
        pass

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
        dataParser1 = DataParser_TCP()
        dataParser1.start()
        dataParser2 = DataParser_UDP()
        dataParser2.start()
        dataParser3 = DataParser_ICMP()
        dataParser3.start()
        nfqueue.run()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()
        nfqueue.unbind()