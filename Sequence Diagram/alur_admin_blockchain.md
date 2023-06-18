sequenceDiagram
User->>+Frontend: Membuat akun
Frontend->>+Backend: Mengirim Data
Backend->>+Backend: Membuat keypairs baru<br>(publicKey dan privateKey)
Backend->>+BigchainDB: Membuat data blockchain baru
Backend->>+Frontend: Menampilan keypairs untuk user
User->>+Frontend: Membuat firewall rule<br>dengan keypair <br>yang barusan digenerate
Frontend->>+Backend: Mengirim Data
Backend->>+BigchainDB: Membuat data blockchain baru
Backend->>+Frontend: Menampilan pesan sukses
User->>+Frontend:Mengedit firewall rule<br>dengan keypair yang salah
Frontend->>+Backend: Mengirim data
Backend->>+BigchainDB: Mengedit data blockchain baru
BigchainDB->>+Backend: Mengirim error karena keypair salah
Backend->>+Frontend: Menampilan pesan error
