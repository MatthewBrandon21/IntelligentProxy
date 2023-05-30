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
import csv
from csv import writer
import statistics
from statistics import mode

firewall_name = "node-firewall"

# Traffic Signature
tcp_signature = {
    "port_dest": 0,
    "dataofs": 0,
    "reserved": 0,
    "flags": "S",
    "window": 0,
    "urgptr": 0,
    "payload_len": 0
}

udp_signature = {
    "port_dest": 0,
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

# logging data
tcp_file_name = "tcp_firewall_network.log"
udp_file_name = "udp_firewall_network.log"
icmp_file_name = "icmp_firewall_network.log"

# Timeseries data
tcp_timeseries_data = []
udp_timeseries_data = []
icmp_timeseries_data = []

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


def firewall(pkt):
    global tcp_timeseries_data
    global udp_timeseries_data
    global icmp_timeseries_data
    global tcp_networklogger
    global udp_networklogger
    global icmp_networklogger
    global tcp_ddos
    global udp_ddos
    global icmp_ddos

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
        # tcp_data = {
        #     "ip_src": sca.src,
        #     "port_src": t.sport,
        #     "port_dest": t.dport,
        #     "seq": t.seq,
        #     "ack": t.ack,
        #     "dataofs": t.dataofs,
        #     "reserved": t.reserved,
        #     "flags": str(t.flags),
        #     "window": t.window,
        #     "chksum": t.chksum,
        #     "urgptr": t.urgptr,
        #     "payload_len": pkt.get_payload_len(),
        # }
        # print(f"sca TCP, connection : {t}, data : {t.fields}, flags: {t.fields['flags']}, timestamp : {pkt.get_timestamp()}, len : {pkt.get_payload_len()}")
        tcp_networklogger.info(f'{sca.src},{str(t.sport)},{str(t.dport)},{str(t.seq)},{str(t.ack)},{str(t.dataofs)},{str(t.reserved)},{str(t.flags)},{str(t.window)},{str(t.chksum)},{str(t.urgptr)},{str(pkt.get_payload_len())}')
        tcp_timeseries = [str(time.perf_counter()), str(t.sport), str(t.dport), str(t.seq), str(t.ack), str(t.dataofs), str(t.reserved), str(t.flags), str(t.window), str(t.chksum), str(t.urgptr), str(pkt.get_payload_len()), str(0)]
        tcp_timeseries_data.append(tcp_timeseries)
    
    if sca.haslayer(UDP):
        t = sca.getlayer(UDP)
        # udp_data = {
        #     "ip_src": sca.src,
        #     "port_src": t.sport,
        #     "port_dest": t.dport,
        #     "len": t.len,
        #     "chksum": t.chksum,
        #     "port_dest": pkt.get_payload_len(),
        # }
        # print(f"sca UDP, connection : {t}, data : {t.fields}, timestamp : {pkt.get_timestamp()}, len : {pkt.get_payload_len()}")
        udp_networklogger.info(f'{sca.src},{str(t.sport)},{str(t.dport)},{str(t.len)},{str(t.chksum)},{str(pkt.get_payload_len())}')
        udp_timeseries = [str(time.perf_counter()), str(t.sport), str(t.dport), str(t.len), str(t.chksum), str(pkt.get_payload_len()), str(0)]
        udp_timeseries_data.append(udp_timeseries)
    
    if sca.haslayer(ICMP):
        t = sca.getlayer(ICMP)
        # Only ICMP echo request
        if(t.code==0 and t.type==8):
            # icmp_data = {
            #     "ip_src": sca.src,
            #     "chksum": t.chksum,
            #     "id": t.id,
            #     "seq": t.seq,
            #     "payload_len": pkt.get_payload_len(),
            # }
            # print(f"sca ICMP, connection : {t}, data : {t.fields}, timestamp : {pkt.get_timestamp()}, len : {pkt.get_payload_len()}")
            icmp_networklogger.info(f'{sca.src},{str(t.chksum)},{str(t.id)},{str(t.seq)},{str(pkt.get_payload_len())}')
            icmp_timeseries = [str(time.perf_counter()), str(t.chksum), str(t.id), str(t.seq), str(pkt.get_payload_len()), str(0)]
            icmp_timeseries_data.append(icmp_timeseries)
    
    # Forward packet to iptables
    pkt.accept()

def find_most(List):
    return(mode(List))

def tcp_comparator(pkt, t):
    global tcp_signature
    if(tcp_signature['port_dest'] == t.dport and
       tcp_signature['dataofs'] == t.dataofs and
       tcp_signature['reserved'] == t.reserved and
       tcp_signature['flags'] == str(t.flags) and
       tcp_signature['window'] == t.window and
       tcp_signature['urgptr'] == t.urgptr and
       tcp_signature['payload_len'] == pkt.get_payload_len()):
        return True
    else:
        return False

def udp_comparator(pkt, t):
    global udp_signature
    if(udp_signature['port_dest'] == t.dport and
       udp_signature['len'] == t.len and
       udp_signature['payload_len'] == pkt.get_payload_len()):
        return True
    else:
        return False

def icmp_comparator(pkt, t):
    global icmp_signature
    if(icmp_signature['id'] == t.id and
       icmp_signature['payload_len'] == pkt.get_payload_len()):
        return True
    else:
        return False

# Handler if file configuration modified
def on_modified(event):
    print(f"{event.src_path} has been modified")
    logging.info(f'{event.src_path} has been modified')
    logging.info('Firewall listener restarting...')
    seedFromFile()

# Data parser to machine learing dataset (will flush logfile every 5 second)
class DataParser(Thread):
    def __init__(self):
        super(DataParser, self).__init__()

        # Data parser configuration
        self.sleep_time = 5
        self.tcp_data_count = 13
        self.udp_data_count = 7
        self.icmp_data_count = 6

    def run(self):
        global tcp_file_name
        global udp_file_name
        global icmp_file_name

        while True:
            # Array for save raw data from file
            tcp_raw_datas = []
            udp_raw_datas = []
            icmp_raw_datas = []

            # Read and parse tcp logfile
            tcp_network_log_file = open(tcp_file_name, 'r')
            tcp_network_lines = tcp_network_log_file.readlines()
            if(len(tcp_network_lines) != 0):
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
                port_dest = []
                seq = []
                ack = []
                dataofs = []
                reserved = []
                flags = []
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
                        port_dest.append(int(data[3]))
                    if(data[4] != "NULL"):
                        seq.append(int(data[4]))
                    if(data[5] != "NULL"):
                        ack.append(int(data[5]))
                    if(data[6] != "NULL"):
                        dataofs.append(int(data[6]))
                    if(data[7] != "NULL"):
                        reserved.append(int(data[7]))
                    if(data[8] != "NULL"):
                        flags.append(self.StringToBytes(data[8]))
                    if(data[9] != "NULL"):
                        window.append(int(data[9]))
                    if(data[10] != "NULL"):
                        chksum.append(int(data[10]))
                    if(data[11] != "NULL"):
                        urgptr.append(int(data[11]))
                    if(data[12] != "NULL"):
                        payload_len.append(int(data[12]))
                
                timestamp_std = np.std(timestamp)
                ip_src_std = np.std(ip_src)
                port_src_std = np.std(port_src)
                port_dest_std = np.std(port_dest)
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

                # Label : 0 Normal, 1 TCP flood
                label = 0

                #Creating headers
                randvar1 = "timestamp_std"
                randvar2 = "ip_src_std"
                randvar3 = "port_src_std"
                randvar4 = "port_dest_std"
                randvar5 = "seq_std"
                randvar6 = "ack_std"
                randvar7 = "dataofs_std"
                randvar8 = "reserved_std"
                randvar9 = "flags_std"
                randvar10 = "window_std"
                randvar11 = "chksum_std"
                randvar12 = "urgptr_std"
                randvar13 = "payload_len_std"
                randvar14 = "rate_connection"
                randvar15 = "label"

                header = []
                header = [randvar1,randvar2,randvar3,randvar4,randvar5,randvar6,randvar7,randvar8,randvar9,randvar10,randvar11,randvar12,randvar13,randvar14,randvar15]

                smart = []
                smart = [timestamp_std,ip_src_std,port_src_std,port_dest_std,seq_std,ack_std,dataofs_std,reserved_std,flags_std,window_std,chksum_std,urgptr_std,payload_len_std,rate_connection,label]
                
                # Append to dataset file
                with open('dataset_tcp.csv', 'a') as datafile:
                    writer = csv.writer(datafile, delimiter=",")
                    # writer.writerow(header)
                    writer.writerow(smart)

                datafile.close()
            
            # Read and parse udp logfile
            udp_network_log_file = open(udp_file_name, 'r')
            udp_network_lines = udp_network_log_file.readlines()
            if(len(udp_network_lines) != 0):
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
                port_dest = []
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
                        port_dest.append(int(data[3]))
                    if(data[4] != "NULL"):
                        len_pkt.append(int(data[4]))
                    if(data[5] != "NULL"):
                        chksum.append(int(data[5]))
                    if(data[6] != "NULL"):
                        payload_len.append(int(data[6]))
                
                timestamp_std = np.std(timestamp)
                ip_src_std = np.std(ip_src)
                port_src_std = np.std(port_src)
                port_dest_std = np.std(port_dest)
                len_std = np.std(len_pkt)
                chksum_std = np.std(chksum)
                payload_len_std = np.std(payload_len)
                rate_connection = total_connection_sum

                # Label : 0 Normal, 1 UDP flood
                label = 0

                #Creating headers
                randvar1 = "timestamp_std"
                randvar2 = "ip_src_std"
                randvar3 = "port_src_std"
                randvar4 = "port_dest_std"
                randvar5 = "len_std"
                randvar6 = "chksum_std"
                randvar7 = "payload_len_std"
                randvar8 = "rate_connection"
                randvar9 = "label"

                header = []
                header = [randvar1,randvar2,randvar3,randvar4,randvar5,randvar6,randvar7,randvar8,randvar9]

                smart = []
                smart = [timestamp_std,ip_src_std,port_src_std,port_dest_std,len_std,chksum_std,payload_len_std,rate_connection,label]
                
                # Append to dataset file
                with open('dataset_udp.csv', 'a') as datafile:
                    writer = csv.writer(datafile, delimiter=",")
                    # writer.writerow(header)
                    writer.writerow(smart)

                datafile.close()
            
            # Read and parse icmp logfile
            icmp_network_log_file = open(icmp_file_name, 'r')
            icmp_network_lines = icmp_network_log_file.readlines()
            if(len(icmp_network_lines) != 0):
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

                # Label : 0 Normal, 1 ICMP flood
                label = 0

                #Creating headers
                randvar1 = "timestamp_std"
                randvar2 = "ip_src_std"
                randvar3 = "chksum_std"
                randvar4 = "id_std"
                randvar5 = "seq_std"
                randvar6 = "payload_len_std"
                randvar7 = "rate_connection"
                randvar8 = "label"

                header = []
                header = [randvar1,randvar2,randvar3,randvar4,randvar5,randvar6,randvar7,randvar8]

                smart = []
                smart = [timestamp_std,ip_src_std,chksum_std,id_std,seq_std,payload_len_std,rate_connection,label]
                
                # Append to dataset file
                with open('dataset_icmp.csv', 'a') as datafile:
                    writer = csv.writer(datafile, delimiter=",")
                    # writer.writerow(header)
                    writer.writerow(smart)

                datafile.close()
            
            # Flush logfiles
            with open(tcp_file_name, 'w'):
                pass
            with open(udp_file_name, 'w'):
                pass
            with open(icmp_file_name, 'w'):
                pass

            # Flush data
            tcp_raw_datas = []
            udp_raw_datas = []
            icmp_raw_datas = []

            # Sleep 5 second
            time.sleep(self.sleep_time)
    
    def StringToBytes(self, data):
        sum = 0
        arrbytes = bytes(data, 'utf-8')
        for i in arrbytes:
            sum = sum + i
        return(sum)

# Timeseries data exporter
class TimeseriesDataExporter(Thread):
    def __init__(self):
        super(TimeseriesDataExporter, self).__init__()

    def run(self):
        global tcp_timeseries_data
        global udp_timeseries_data
        global icmp_timeseries_data

        while True:
            if(len(tcp_timeseries_data) >= 25):
                with open('dataset_tcp_timeseries.csv', 'a') as f_object:
                    writer_object = writer(f_object)
                    for data in tcp_timeseries_data:
                        writer_object.writerow(data)
                    f_object.close()
                tcp_timeseries_data = []
            if(len(udp_timeseries_data) >= 25):
                with open('dataset_udp_timeseries.csv', 'a') as f_object:
                    writer_object = writer(f_object)
                    for data in udp_timeseries_data:
                        writer_object.writerow(data)
                    f_object.close()
                udp_timeseries_data = []
            if(len(icmp_timeseries_data) >= 25):
                with open('dataset_icmp_timeseries.csv', 'a') as f_object:
                    writer_object = writer(f_object)
                    for data in icmp_timeseries_data:
                        writer_object.writerow(data)
                    f_object.close()
                icmp_timeseries_data = []

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
        dataParser1 = DataParser()
        dataParser1.start()
        dataExporter1 = TimeseriesDataExporter()
        dataExporter1.start()
        nfqueue.run()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()
        nfqueue.unbind()