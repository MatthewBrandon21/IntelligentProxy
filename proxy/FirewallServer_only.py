from netfilterqueue import NetfilterQueue
from scapy.all import *
import json
import time
import datetime
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import logging
from functools import lru_cache

firewall_name = "node-firewall"

# Firewall config
ListOfBannedIpAddr = []
ListOfBannedPorts = []
ListOfBannedPrefixes = []
ListOfWebserverIpAddr = []
ListOfWebserverPorts = []

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

@lru_cache
def isWebserverIp(ip):
    if ip in ListOfWebserverIpAddr:
        return true
    return false

@lru_cache
def isBannedIp(ip):
    if ip in ListOfBannedIpAddr:
        print(ip, "is a incoming IP address that is banned by the firewall.")
        logging.info(f'{ip} is a incoming IP address that is banned by the firewall.')
        return true
    return false

@lru_cache
def isBannedPort(port):
    if port in ListOfBannedPorts:
        print(port, "is a destination port that is blocked by the firewall.")
        logging.info(f'{port} is a destination port that is blocked by the firewall.')
        return true
    return false

@lru_cache
def isBannedPrefix(prefix):
    if True in [prefix.find(suff) == 0 for suff in ListOfBannedPrefixes]:
        print("Prefix of " + prefix + " is banned by the firewall.")
        logging.info(f'Prefix of {prefix} is banned by the firewall.')
        return true
    return false

def firewall(pkt):
    # parse packet data from incomming connection
    sca = IP(pkt.get_payload())

    # Webserver whitelist
    if isWebserverIp(sca.src):
        pkt.accept()
        return

    # IP address firewall
    if isBannedIp(sca.src):
        pkt.drop()
        return

    # Port firewall
    t = None
    if sca.haslayer(TCP):
        t = sca.getlayer(TCP)
    else if sca.haslayer(UDP):
        t = sca.getlayer(UDP)
    if (t != None):
        if isBannedPort(t.dport):
            pkt.drop()
            return

    # Prefixes firewall
    if isBannedPrefix(sca.src):
        pkt.drop()
        return
    
    # Forward packet to iptables
    pkt.accept()

# Handler if file configuration modified
def on_modified(event):
    print(f"{event.src_path} has been modified, time : {datetime.datetime.now()}")
    logging.info(f'{event.src_path} has been modified')
    logging.info('Firewall listener restarting...')
    seedFromFile()

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
        nfqueue.run()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()
        nfqueue.unbind()
