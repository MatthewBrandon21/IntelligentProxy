sequenceDiagram
Client->>+Firewall: Paket baru masuk
Firewall->>+Log File: Menambahkan paket baru
Log File->>+Dataparser: Membaca paket
Dataparser->>+Dataparser: Melakukan preprocessing dan transformasi data
Dataparser->>+Machine Learning: Melakukan prediksi
Machine Learning->>+ Firewall: Mengembalikan nilai prediksi
alt Terdeteksi DDoS
Firewall->>+Machine Learning: Membuat signature paket
Firewall->>+Firewall: Mengaktifkan mode DDoS
alt Mode DDoS:
Firewall->>+Machine Learning: Membandingkan Paket
Machine Learning->>+ Firewall: Mengembalikan nilai prediksi
alt Jika sama:
Firewall->>+Firewall: Menolak paket
else Tidak sama:
Firewall->>+Forwarder: Melanjutkan paket
end
end
else Tidak terdeteksi DDoS:
Firewall->>+Forwarder: Melanjutkan paket
end
Forwarder->>+Webserver: Melanjutkan paket
Webserver->>+Forwarder: Mengirimkan paket yang diminta
Forwarder->>+Client: Mengirimkan paket yang diminta
