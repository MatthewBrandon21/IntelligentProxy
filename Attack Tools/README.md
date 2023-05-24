hping3 -> sudo apt install hping3 -y / sudo yum -y install hping3

Scenario
Benchmarking
a. Apache Bench
b. Apache JMeter
c. Iperf

1. Normal
   a. Video (UDP) + Audio (TCP) Streaming -> 2 / 3 Video yang berbeda ~10 menit
   b. Random request generator -> 11 endpoint (flask + nodeJS), 5 menit, 2 / 3 instance
   c. hping3 normal 5 - 10 menit

2. SYN Flood
   a. hping3
   a. sudo hping3 -S --flood -V -p 3002 192.168.29.128
   b. sudo hping3 192.168.29.128 -q -n -d 120 -S -p 3002 --flood --rand-source
   c. AllInOne.py
   d. ICMP_flood2.py

3. ICMP Flood
   a. hping3
   a. sudo hping3 --flood –V –i eth0 192.168.29.128
   b. hping3 --icmp --flood 192.168.29.128
   c. ICMP_flood.py
   d. ICMP_flood2.py

4. TCP Flood
   a. TCP SYN -> TCP_flood.py
   b. TCP Get -> TCP_flood2.py
   c. TCP Get -> TCP_flood3.py
   d. RavenStrom

5. UDP Flood
   a. UDP_flood.py
   b. RavenStrom

6. HTTP Flood
   a. GoldenEye
   b. AllInOne.py
   c. HTTP_flood.py

7. Xmas Flood
   a. ICMP_flood2.py
