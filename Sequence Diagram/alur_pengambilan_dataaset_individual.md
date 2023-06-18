sequenceDiagram
paket->>+Listener Controller: paket datang
Listener Controller->>+Logs File: Menambahkan informasi paket
Dataparser Controller->>+Logs File: Mengambil semua data
Dataparser Controller->>+Dataparser Controller: Merangkum sample dengan proses kalkulasi
Dataparser Controller->>+Logs File: Menghapus semua data
Dataparser Controller->>+Dataparser Controller: Sleep selama N detik
paket->>+Listener Controller: paket datang
Listener Controller->>+Logs File: Menambahkan informasi paket
paket->>+Listener Controller: paket datang
Listener Controller->>+Logs File: Menambahkan informasi paket
Dataparser Controller->>+Logs File: Mengambil semua data
Dataparser Controller->>+Dataparser Controller: Merangkum sample dengan proses kalkulasi
Dataparser Controller->>+Logs File: Menghapus semua data
Dataparser Controller->>+Dataparser Controller: Sleep selama N detik
