# pip install psutil

import time
import psutil

total = 0
average = 0
count = 0

def print_usage(cpu_usage, mem_usage):
    global total
    global average
    global count

    total = total + cpu_usage
    count = count + 1
    average = total / count
    # cpu_percent = (cpu_usage / 100.0)
    # mem_percent = (mem_usage / 100.0)
    print(f"\rCPU Usage: {cpu_usage:.2f}% | ", end="")
    print(f"Memory Usage: {mem_usage:.2f}% | ", end="")
    print(f"Average CPU Usage: {average:.2f}%", end="\r")

    if(count == 300):
        total = 0
        average = 0
        count = 0

while True:
    # print(psutil.cpu_percent())
    # print(psutil.virtual_memory().percent)
    print_usage(psutil.cpu_percent(), psutil.virtual_memory().percent)
    time.sleep(1)