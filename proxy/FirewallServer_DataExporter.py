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

firewall_name = "node-firewall"

# Firewall config
ListOfBannedIpAddr = []
ListOfBannedPorts = []
ListOfBannedPrefixes = []
ListOfWebserverIpAddr = []
ListOfWebserverPorts = []

# logging data
tcp_log_file_name = "tcp_firewall_network.log"
udp_log_file_name = "udp_firewall_network.log"
icmp_log_file_name = "icmp_firewall_network.log"

# dataset individual data
tcp_dataset_individual_file_name = "tcp_dataset_individual.log"
udp_dataset_individual_file_name = "udp_dataset_individual.log"
icmp_dataset_individual_file_name = "icmp_dataset_individual.log"

# dataset timeseries data
tcp_dataset_timeseries_file_name = "tcp_dataset_timeseries.log"
udp_dataset_timeseries_file_name = "udp_dataset_timeseries.log"
icmp_dataset_timeseries_file_name = "icmp_dataset_timeseries.log"

# Timeseries data
tcp_timeseries_data = []
udp_timeseries_data = []
icmp_timeseries_data = []

# Timeseries configuration
tcp_timeseries_len = 200
udp_timeseries_len = 200
icmp_timeseries_len = 200

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
    global tcp_timeseries_data
    global udp_timeseries_data
    global icmp_timeseries_data
    global tcp_networklogger
    global udp_networklogger
    global icmp_networklogger
    global tcp_timeseries_len
    global udp_timeseries_len
    global icmp_timeseries_len

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
            if(len(tcp_timeseries_data) <= tcp_timeseries_len):
                tcp_timeseries = [str(t.sport), str(t.seq), str(t.ack), str(t.dataofs), str(t.reserved), str(t.flags), str(t.window), str(t.chksum), str(t.urgptr), str(pkt.get_payload_len())]
                tcp_timeseries_data.append(tcp_timeseries)
    
    if sca.haslayer(UDP):
        t = sca.getlayer(UDP)
        if t.dport in ListOfWebserverPorts:
            udp_networklogger.info(f'{sca.src},{str(t.sport)},{str(t.len)},{str(t.chksum)},{str(pkt.get_payload_len())}')
            if(len(udp_timeseries_data) <= udp_timeseries_len):
                udp_timeseries = [str(t.sport), str(t.len), str(t.chksum), str(pkt.get_payload_len())]
                udp_timeseries_data.append(udp_timeseries)
    
    if sca.haslayer(ICMP):
        t = sca.getlayer(ICMP)
        # Only ICMP echo request
        if(t.code==0 and t.type==8):
            icmp_networklogger.info(f'{sca.src},{str(t.chksum)},{str(t.id)},{str(t.seq)},{str(pkt.get_payload_len())}')
            if(len(icmp_timeseries_data) <= icmp_timeseries_len):
                icmp_timeseries = [str(t.chksum), str(t.id), str(t.seq), str(pkt.get_payload_len())]
                icmp_timeseries_data.append(icmp_timeseries)
    
    # Forward packet to iptables
    pkt.accept()

# Handler if file configuration modified
def on_modified(event):
    print(f"{event.src_path} has been modified")
    logging.info(f'{event.src_path} has been modified')
    logging.info('Firewall listener restarting...')
    seedFromFile()

# Data parser to machine learing dataset (will flush logfile every x second)
class DataParser(Thread):
    def __init__(self):
        super(DataParser, self).__init__()

        # Data parser configuration
        self.sleep_time = 5
        self.tcp_data_count = 12
        self.udp_data_count = 6
        self.icmp_data_count = 6

    def run(self):
        global tcp_log_file_name
        global udp_log_file_name
        global icmp_log_file_name
        global tcp_dataset_individual_file_name
        global udp_dataset_individual_file_name
        global icmp_dataset_individual_file_name

        while True:
            # Array for save raw data from file
            tcp_raw_datas = []
            udp_raw_datas = []
            icmp_raw_datas = []

            # Read and parse tcp logfile
            tcp_network_log_file = open(tcp_log_file_name, 'r')
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
                        seq.append(int(data[3]))
                    if(data[4] != "NULL"):
                        ack.append(int(data[4]))
                    if(data[5] != "NULL"):
                        dataofs.append(int(data[5]))
                    if(data[6] != "NULL"):
                        reserved.append(int(data[6]))
                    if(data[7] != "NULL"):
                        flags.append(self.StringToBytes(data[7]))
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

                # Label : 0 Normal, 1 TCP flood
                label = 0

                row = []
                row = [timestamp_std,ip_src_std,port_src_std,seq_std,ack_std,dataofs_std,reserved_std,flags_std,window_std,chksum_std,urgptr_std,payload_len_std,rate_connection,label]
                
                # Append to dataset file
                with open(tcp_dataset_individual_file_name, 'a') as datafile:
                    writer = csv.writer(datafile, delimiter=",")
                    writer.writerow(row)
                datafile.close()
            
            # Read and parse udp logfile
            udp_network_log_file = open(udp_log_file_name, 'r')
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

                # Label : 0 Normal, 1 UDP flood
                label = 0

                row = []
                row = [timestamp_std,ip_src_std,port_src_std,len_std,chksum_std,payload_len_std,rate_connection,label]
                
                # Append to dataset file
                with open(udp_dataset_individual_file_name, 'a') as datafile:
                    writer = csv.writer(datafile, delimiter=",")
                    writer.writerow(row)
                datafile.close()
            
            # Read and parse icmp logfile
            icmp_network_log_file = open(icmp_log_file_name, 'r')
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

                row = []
                row = [timestamp_std,ip_src_std,chksum_std,id_std,seq_std,payload_len_std,rate_connection,label]
                
                # Append to dataset file
                with open(icmp_dataset_individual_file_name, 'a') as datafile:
                    writer = csv.writer(datafile, delimiter=",")
                    writer.writerow(row)
                datafile.close()
            
            # Flush logfiles
            with open(tcp_log_file_name, 'w'):
                pass
            with open(udp_log_file_name, 'w'):
                pass
            with open(icmp_log_file_name, 'w'):
                pass

            # Flush data
            tcp_raw_datas = []
            udp_raw_datas = []
            icmp_raw_datas = []

            # Sleep x second
            time.sleep(self.sleep_time)

    def StringToBytes(self, data):
        sum = 0
        arrbytes = bytes(data, 'utf-8')
        for i in arrbytes:
            sum = sum + i
        return(sum)

# TCP Timeseries data exporter
class TimeseriesDataExporter_TCP(Thread):
    def __init__(self):
        super(TimeseriesDataExporter_TCP, self).__init__()

    def run(self):
        global tcp_timeseries_data
        global tcp_dataset_timeseries_file_name
        global tcp_timeseries_len

        while True:
            if(len(tcp_timeseries_data) >= (tcp_timeseries_len+1)):
                with open(tcp_dataset_timeseries_file_name, 'a') as f_object:
                    writer_object = writer(f_object)
                    for data in tcp_timeseries_data:
                        writer_object.writerow(data)
                    f_object.close()
                tcp_timeseries_data = []

# UDP Timeseries data exporter
class TimeseriesDataExporter_UDP(Thread):
    def __init__(self):
        super(TimeseriesDataExporter_UDP, self).__init__()

    def run(self):
        global udp_timeseries_data
        global udp_dataset_timeseries_file_name
        global udp_timeseries_len

        while True:
            if(len(udp_timeseries_data) >= (udp_timeseries_len+1)):
                with open(udp_dataset_timeseries_file_name, 'a') as f_object:
                    writer_object = writer(f_object)
                    for data in udp_timeseries_data:
                        writer_object.writerow(data)
                    f_object.close()
                udp_timeseries_data = []

# ICMP Timeseries data exporter
class TimeseriesDataExporter_ICMP(Thread):
    def __init__(self):
        super(TimeseriesDataExporter_ICMP, self).__init__()

    def run(self):
        global icmp_timeseries_data
        global icmp_dataset_timeseries_file_name
        global icmp_timeseries_len

        while True:
            if(len(icmp_timeseries_data) >= (icmp_timeseries_len+1)):
                with open(icmp_dataset_timeseries_file_name, 'a') as f_object:
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
    tcp_networkloggerhandler = logging.FileHandler(tcp_log_file_name)
    tcp_networkloggerformatter = logging.Formatter('%(created)f,%(message)s')
    tcp_networkloggerhandler.setFormatter(tcp_networkloggerformatter)
    #set filter to log only INFO lines
    tcp_networkloggerhandler.addFilter(LoggerFilter(logging.INFO))
    tcp_networklogger.addHandler(tcp_networkloggerhandler)

    #create a UDP logger
    udp_networklogger = logging.getLogger('udp_networklogger')
    udp_networklogger.setLevel(logging.INFO)
    udp_networkloggerhandler = logging.FileHandler(udp_log_file_name)
    udp_networkloggerformatter = logging.Formatter('%(created)f,%(message)s')
    udp_networkloggerhandler.setFormatter(udp_networkloggerformatter)
    #set filter to log only INFO lines
    udp_networkloggerhandler.addFilter(LoggerFilter(logging.INFO))
    udp_networklogger.addHandler(udp_networkloggerhandler)

    #create a ICMP logger
    icmp_networklogger = logging.getLogger('icmp_networklogger')
    icmp_networklogger.setLevel(logging.INFO)
    icmp_networkloggerhandler = logging.FileHandler(icmp_log_file_name)
    icmp_networkloggerformatter = logging.Formatter('%(created)f,%(message)s')
    icmp_networkloggerhandler.setFormatter(icmp_networkloggerformatter)
    #set filter to log only INFO lines
    icmp_networkloggerhandler.addFilter(LoggerFilter(logging.INFO))
    icmp_networklogger.addHandler(icmp_networkloggerhandler)

    # Logging initialization
    logging.basicConfig(filename='firewall_application.log', encoding='utf-8', level=logging.DEBUG,
                        format='%(created)f,%(message)s')
    
    # Make sure logging file is empty
    with open(tcp_log_file_name, 'w'):
        pass
    with open(udp_log_file_name, 'w'):
        pass
    with open(icmp_log_file_name, 'w'):
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