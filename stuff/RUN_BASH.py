import os
import time
import subprocess
import datetime

print(f'Now time : {datetime.datetime.now()}')
print(f'Now pert_counter : {time.perf_counter()}')
# os.system("timeout 20s sudo hping3 -S --flood -p 3001 192.168.29.1")
proc = subprocess.Popen(['timeout 20s sudo hping3 -S --flood -p 3001 192.168.29.1'], shell=True)
time.sleep(10)
proc.terminate()