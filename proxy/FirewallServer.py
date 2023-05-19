from netfilterqueue import NetfilterQueue
from scapy.all import *
import json
import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler

# Firewall config
ListOfBannedIpAddr = []
ListOfBannedPorts = []
ListOfBannedPrefixes = []

# Seed from file function
def seedFromFile():
    global ListOfBannedIpAddr
    global ListOfBannedPorts
    global ListOfBannedPrefixes
    try:
        file = open("FirewallRules.json","r")
        data = json.load(file)
        file.close()

        # List of banned ip addresses
        if("ListOfBannedIpAddr" in data):
            if(type(data["ListOfBannedIpAddr"])==list):
                ListOfBannedIpAddr = data["ListOfBannedIpAddr"]
            else:
                ListOfBannedIpAddr = []
        else:
            ListOfBannedIpAddr = []
        
        # List of banned ports
        if("ListOfBannedPorts" in data):
            if(type(data["ListOfBannedPorts"])==list):
                ListOfBannedPorts = data["ListOfBannedPorts"]
            else:
                ListOfBannedPorts = []
        else:
            ListOfBannedPorts = []
        
        # List of banned prefixes, e.g. 172.x.x.x
        if("ListOfBannedPrefixes" in data):
            if(type(data["ListOfBannedPrefixes"])==list):
                ListOfBannedPrefixes = data["ListOfBannedPrefixes"]
            else:
                ListOfBannedPrefixes = []
        else:
            ListOfBannedPrefixes = []
    
    except FileNotFoundError:
        ListOfBannedIpAddr = []
        ListOfBannedPorts = []
        ListOfBannedPrefixes = []

def firewall(pkt):
    # parse packet data from incomming connection
	sca = IP(pkt.get_payload())
    
    # IP address firewall
	if(sca.src in ListOfBannedIpAddr):
		print(sca.src, "is a incoming IP address that is banned by the firewall.")
		pkt.drop()
		return 
    
    # TCP Port firewall
	if(sca.haslayer(TCP)):
		t = sca.getlayer(TCP)
		if(t.dport in ListOfBannedPorts):
			print(t.dport, "is a destination port that is blocked by the firewall.")
			pkt.drop()
			return 
    
    # UDP Port firewall
	if(sca.haslayer(UDP)):
		t = sca.getlayer(UDP)
		if(t.dport in ListOfBannedPorts):
			print(t.dport, "is a destination port that is blocked by the firewall.")
			pkt.drop()
			return 
    
    # Prefixes firewall
	if(True in [sca.src.find(suff)==0 for suff in ListOfBannedPrefixes]):
		print("Prefix of " + sca.src + " is banned by the firewall.")
		pkt.drop()
		return
	
    # Forward packet to iptables
	pkt.accept()

# Handler if file configuration modified
def on_modified(event):
    print(f"{event.src_path} has been modified")
    seedFromFile()

if __name__ == "__main__":
    # Watchdog initialization
    patterns = ["*"]
    ignore_patterns = None
    ignore_directories = False
    case_sensitive = True
    my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
    my_event_handler.on_modified = on_modified
    path = "."
    go_recursively = True
    my_observer = Observer()
    my_observer.schedule(my_event_handler, path, recursive=go_recursively)
    my_observer.start()

    # nfqueue initialization
    nfqueue = NetfilterQueue()
    nfqueue.bind(1,firewall)
    try:
        seedFromFile()
        nfqueue.run()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()
        nfqueue.unbind()