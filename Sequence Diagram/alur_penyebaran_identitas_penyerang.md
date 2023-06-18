sequenceDiagram
Forwarder->>+Machine Learning: Mendeteksi paket
Machine Learning->>+Machine Learning: Memprediksi paket
Machine Learning->>+Forwarder: Mengembalikan hasil prediksi<br>dan merupakan serangan DDoS
Forwarder->>+Backend Node 1: Mengirimkan informasi serangan DDoS
Forwarder->>+Firewall Node 1: Mengupdate firewall rule
Backend Node 1->>+BigchainDB: Menambahkan data ke blockhain
Backend Node 1->>+Backend Node 2: Melakukan konsesus
Backend Node 2->>+BigchainDB: Mengambil data terbaru
Backend Node 2->>+Firewall Node 2: Mengupdate firewall rule
