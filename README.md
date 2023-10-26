# Intelligent Proxy

DDoS Mitigation Proxy System Based on Machine Learning and Blockchain

with machine learning detection and identification, system can continue to forward packets normally while blocking packets that include sequence DDoS attack.

Distributed proxy system to mitigate DDoS attack for final year projects. This system has multithreaded for multiclient reverse proxy for packet sniffer and high throughput by designing multiprocessing firewall controller based on packet signature and firewall rules. Comparing across 7 machine learing and deep learning algorithm such as Bidirectional LSTM, SVM, Naive Bayes, KNN, Linear Regresion, Random Forest, and DNN. Use consensus algoritm and blockchain based distributed database BigchainDB for distributing attacker information for reducing time to mitigate (TTM).

To find data features, using standard deviation and variance population statistic to generate stocastic features. From related source the characteristic of DDoS attack is distribution (source), concentration (destination), and high traffic abruptness (payload).

## Roadmap

- Upload all assets to this repository including test result

- Finalizing documentation (for now please see my research paper on this root repository)

- Looking for alternatives netfilterQueue that causes bootleneck in network throughput

- Caching for datasource (especially for firewall controller)

## Tech Stack

**Frontend:** ReactJS, Axios, react-router-dom, jwt-decode, Bulma CSS

**Backend:** NodeJS, ExpressJS, bigchaindb-orm, democracyJS, node-cron, jsonwebtoken

**Firewall:** Python, netFilterqueue, Tensorflow, Sklearn, watchdog-observer, logging, threading, numpy

**Reverse Proxy:** Python, Socket, threading, Tensorflow, Sklearn

**Database:** Python 3.6, BigchainDB, Tendermint, MongoDB, Monit

All running on VM with 8 core and 8GB ram, Ubuntu 22.04.2 LTS

## Features

- Distributed System
- Machine learning detection and identification
- Immutable and distributed database
- Round robin load balancer
- Caching proxy

## Demo

https://www.youtube.com/watch?v=fETmy9wb9RY&t=19s&ab_channel=MatthewBrandonDani

## Run Locally

Make sure you have install and run BigchainDB network in each nodes.

Clone the project

```bash
  git clone https://github.com/MatthewBrandon21/IntelligentProxy
```

Go to the ./proxy directory for proxy, ./frontend directory, & ./backend directory

```bash
  cd ./IntelligentProxy/proxy
```

```bash
  cd ./IntelligentProxy/frontend
```

```bash
  cd ./IntelligentProxy/backend
```

Install dependencies

```bash
  pip install requirements.txt
```

```bash
  npm install
```

Start the backend and frontend

```bash
  npm run start
```

Start the firewall controller

```bash
  sudo iptables -I INPUT -d 192.168.29.0/24 -j NFQUEUE --queue-num 1
```

```bash
  sudo python3 FirewallServer.py
```

Start the proxy controller

```bash
  sudo python3 MultithreadedProxyServer.py
```

## Environment Variables

To run this project, you will need to add the following environment variables to these files :

- ProxyConfig.json -> for proxy and load balancer configuration
- FirewallRules.json -> for firewall rules and banned ip, port, or prefix
- bigchaindb.config.json -> connection to BigchainDB instance

## Acknowledgements

- [Official Campus Publication](https://kc.umn.ac.id/26055/)
- [Python Socket](https://docs.python.org/3/library/socket.html)
- [Python netfilterQueue](https://pypi.org/project/NetfilterQueue/)
- [BigchainDB Github](https://github.com/bigchaindb/bigchaindb)
