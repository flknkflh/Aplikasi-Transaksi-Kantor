# Menguji lintas beberapa komputer

Dua uji terpisah, bisa dilakukan salah satu atau dua-duanya:

- **Bagian 1 - Aplikasi lewat LAN** (gampang, sekitar 10 menit): satu komputer jadi server, komputer lain
  buka browser sebagai "kantor" berbeda. Ini menguji konsep produk yang sebenarnya.
- **Bagian 2 - Blockchain benar-benar tersebar** (lab, perlu waktu dan ketelitian): tiap komputer
  menjalankan node Fabric miliknya sendiri, saling terhubung lewat LAN - mensimulasikan tiap
  kantor punya node sendiri seperti dibahas di ADR-0001/percakapan sebelumnya.

Keduanya bisa jalan bersamaan (server aplikasi di Komputer A, ditambah Komputer B menjalankan
peer blockchain-nya sendiri) - itu simulasi paling mendekati produksi asli.

---

## Bagian 1 - Aplikasi lewat LAN (server + klien di komputer lain)

### Di Komputer A (yang jadi server)

```sh
# 1) cari alamat IP LAN komputer ini
ipconfig                     # cari "IPv4 Address" di adapter WiFi/Ethernet aktif, mis. 192.168.1.10

# 2) sebelum start, atur alamat publik supaya link/QR yang dibuat server menunjuk ke IP ini,
#    bukan localhost (edit deploy/office/.env, atau tambahkan langsung):
cd deploy/office
echo "PQC_PUBLIC_BASE_URL=http://192.168.1.10:18099" >> .env

# 3) jalankan seperti biasa
docker compose up -d --build
bash seed.sh
```

### Izinkan komputer lain masuk (Windows Firewall di Komputer A)

Docker sudah otomatis membuka port ke semua alamat, tapi Windows Firewall biasanya memblokir
koneksi masuk dari komputer lain secara default. Jalankan di PowerShell sebagai Administrator
di Komputer A:

```powershell
New-NetFirewallRule -DisplayName "Arsip PQC HTTP" -Direction Inbound -Protocol TCP -LocalPort 18098,18099 -Action Allow
New-NetFirewallRule -DisplayName "Arsip PQC HTTPS" -Direction Inbound -Protocol TCP -LocalPort 18443,18444 -Action Allow
```

### Di komputer lain (Komputer B, C, ...)

Buka browser ke `http://192.168.1.10:18099/app/` (ganti IP sesuai Komputer A). Banner "Server
tujuan" akan menampilkan alamat itu - konfirmasi visual bahwa memang terhubung ke server yang
benar. Login dengan akun demo kantor berbeda di tiap komputer, misalnya:

| Komputer | Akun |
|---|---|
| B | pengirim.a@local / pengirim12345 (Kantor Cabang A) |
| C | pengirim.b@local / pengirim12345 (Kantor Cabang B) |
| A sendiri (tab lain) | admin@local / admin12345 - lihat kiriman dari B dan C masuk bersamaan |

Kalau mau pakai HTTPS (TLS 1.3 hybrid PQC, ADR-0009): pastikan `TLS_HOSTS` di `.env` memuat IP
Komputer A juga (bukan cuma localhost,127.0.0.1), lalu buka `https://192.168.1.10:18443/app/` -
browser akan warning sertifikat self-signed, klik lanjutkan (wajar, lihat deploy/office/TLS.md).

---

## Bagian 2 - Blockchain Fabric benar-benar tersebar ke 2 komputer

Sebelum mulai, baca ini: ini memakai fabric-samples/test-network bawaan Hyperledger, yang
aslinya dirancang untuk satu mesin saja. Panduan ini memecahnya jadi dua file docker-compose
(network/multi-host-lab/computer-a.yaml dan computer-b.yaml) yang sama persis dengan aslinya,
ditambah satu hal: extra_hosts, supaya container di satu komputer bisa menemukan container di
komputer lain lewat nama domain yang sudah tertanam di sertifikat TLS Fabric
(peer0.org1.example.com, dst) - tanpa perlu membuat ulang sertifikat.

Sudah divalidasi sintaksnya; belum diuji nyata lintas dua mesin fisik (tidak ada akses ke
komputer kedua dari sini) - jalankan dan laporkan kalau ada yang macet untuk dibantu debug dari
pesan errornya.

### Ringkasan pembagian

| | Komputer A | Komputer B |
|---|---|---|
| Menjalankan | orderer.example.com + peer0.org1.example.com (Kantor A) | peer0.org2.example.com (Kantor B) |
| Port ke LAN | 7050, 7051, 7053, 9443, 9444 | 9051, 9445 |

CA server tidak perlu ikut disebar - tugasnya cuma menerbitkan sertifikat sekali di awal; begitu
sertifikat sudah ada di folder organizations/, peer dan orderer cukup membaca file itu, CA-nya
sendiri tidak perlu terus menyala.

### Langkah 0 - Siapkan materi kunci/sertifikat (di Komputer A saja)

Kalau belum pernah, jalankan bootstrap normal dulu satu kali di Komputer A untuk membuat
identitas kriptografi semua pihak (Kantor A, Kantor B, dan orderer) - nanti sebagian isinya
disalin ke Komputer B. Ini konsorsium sederhana di mana satu pihak (Komputer A, mewakili
penyelenggara lab) yang menerbitkan identitas semua peserta; produksi sungguhan biasanya tiap
kantor punya CA sendiri (lihat ADR-0001 dan pembahasan sebelumnya), tapi untuk uji fungsional
lintas-mesin ini sudah cukup mewakili.

```sh
cd network
bash bootstrap.sh          # kalau belum pernah / mau mulai dari bersih
bash teardown.sh           # matikan network single-host bawaan skrip ini SETELAH bootstrap selesai
                            # (chaincode sudah ter-package; folder organizations/ TETAP ada)
```

### Langkah 1 - Salin materi Kantor B ke Komputer B

Dari Komputer A, salin folder ini ke Komputer B (lewat USB, network share, atau scp/rsync bila
sudah terhubung SSH) - struktur foldernya harus sama persis relatif terhadap network/:

```
network/vendor/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com/
network/vendor/fabric-samples/test-network/organizations/ordererOrganizations/example.com/
network/vendor/fabric-samples/test-network/compose/docker/peercfg/
network/multi-host-lab/computer-b.yaml
```

Cara paling gampang: salin saja seluruh folder network/ (termasuk vendor/) ke Komputer B - lebih
besar tapi tidak perlu pilah-pilah file dan pasti tidak ada yang ketinggalan. Komputer B juga
perlu Docker Desktop terpasang, dan image Fabric sudah tertarik (docker pull
hyperledger/fabric-peer:2.5.16), atau jalankan install-fabric.sh ... docker seperti yang
dilakukan bootstrap.sh - lihat isinya untuk versi persis yang dipin.

### Langkah 2 - Cari IP LAN kedua komputer

Di kedua komputer: `ipconfig`. Catat IPv4 masing-masing, misal Komputer A = 192.168.1.10,
Komputer B = 192.168.1.11.

### Langkah 3 - Buka port di Windows Firewall

Di Komputer A (PowerShell Administrator):
```powershell
New-NetFirewallRule -DisplayName "Fabric OrdererOrg1" -Direction Inbound -Protocol TCP -LocalPort 7050,7051,7053,9443,9444 -Action Allow
```

Di Komputer B (PowerShell Administrator):
```powershell
New-NetFirewallRule -DisplayName "Fabric Org2" -Direction Inbound -Protocol TCP -LocalPort 9051,9445 -Action Allow
```

### Langkah 4 - Nyalakan tiap bagian

Di Komputer A:
```sh
cd network/multi-host-lab
PEER0_ORG2_HOST_IP=192.168.1.11 docker compose -f computer-a.yaml up -d
docker compose -f computer-a.yaml ps
```

Di Komputer B:
```sh
cd network/multi-host-lab
PEER0_ORG1_HOST_IP=192.168.1.10 docker compose -f computer-b.yaml up -d
docker compose -f computer-b.yaml ps

# uji koneksi ke Komputer A dari DALAM container (bukti extra_hosts + firewall berhasil):
docker exec peer0.org2.example.com sh -c "getent hosts orderer.example.com"
# harus menampilkan 192.168.1.10 - kalau tidak, extra_hosts/firewall belum benar
```

### Langkah 5 - Buat channel, gabungkan Komputer B, pasang chaincode

Perintah peer CLI di bawah dijalankan dari CLI lokal masing-masing komputer
(network/vendor/fabric-samples/test-network/../bin/peer), menunjuk ke peer/orderer miliknya
sendiri lewat variabel lingkungan - pola yang sama dengan test-network/scripts/envVar.sh, cuma
sekarang dijalankan dari dua mesin berbeda alih-alih satu shell yang sama.

Di Komputer A (buat channel, join peer0.org1):
```sh
cd network/vendor/fabric-samples/test-network
export PATH="$PWD/../bin:$PATH"
export FABRIC_CFG_PATH="$PWD/../config"
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_MSPCONFIGPATH=$PWD/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_TLS_ROOTCERT_FILE=$PWD/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_ADDRESS=localhost:7051
export ORDERER_CA=$PWD/organizations/ordererOrganizations/example.com/msp/tlscacerts/tlsca.example.com-cert.pem

# channel sudah pernah dibuat oleh bootstrap.sh (artefaknya ada di ./channel-artifacts/):
peer channel join -b ./channel-artifacts/ledgerchannel.block
```

Di Komputer B (ambil genesis block dari orderer di Komputer A lewat jaringan, lalu join):
```sh
cd network/vendor/fabric-samples/test-network
export PATH="$PWD/../bin:$PATH"
export FABRIC_CFG_PATH="$PWD/../config"
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org2MSP
export CORE_PEER_MSPCONFIGPATH=$PWD/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
export CORE_PEER_TLS_ROOTCERT_FILE=$PWD/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_ADDRESS=localhost:9051
export ORDERER_CA=$PWD/organizations/ordererOrganizations/example.com/msp/tlscacerts/tlsca.example.com-cert.pem

peer channel fetch 0 ./ledgerchannel.block -c ledgerchannel -o orderer.example.com:7050 --tls --cafile "$ORDERER_CA"
peer channel join -b ./ledgerchannel.block
```

Kalau `peer channel fetch` berhasil, itu buktinya Komputer B sudah bisa bicara ke orderer di
Komputer A lewat jaringan sungguhan - bagian tersulit sudah lewat.

### Langkah 6 - Pasang dan setujui chaincode dari kedua sisi

Chaincode-nya (transaction, asset) sudah ada dan sudah teruji di chaincode/ - tidak perlu
ditulis ulang, cuma dipasang ke peer di kedua komputer. Paket chaincode (.tar.gz) harus identik
di kedua sisi (salin file paketnya dari Komputer A ke Komputer B, jangan package ulang di
masing-masing, supaya package ID-nya sama):

```sh
# di Komputer A: package sekali
peer lifecycle chaincode package transaction.tar.gz --path ../../../../chaincode/transaction --lang golang --label transaction_1.0
# salin transaction.tar.gz ke Komputer B (USB/scp)

# di TIAP komputer (dengan env var org masing-masing dari Langkah 5):
peer lifecycle chaincode install transaction.tar.gz
peer lifecycle chaincode queryinstalled     # catat Package ID yang tercetak

# di TIAP komputer: setujui untuk org masing-masing
peer lifecycle chaincode approveformyorg -o orderer.example.com:7050 --tls --cafile "$ORDERER_CA" \
  --channelID ledgerchannel --name transaction --version 1.0 --package-id PACKAGE_ID_DISINI --sequence 1

# dari SALAH SATU komputer saja, setelah kedua org approve:
peer lifecycle chaincode checkcommitreadiness --channelID ledgerchannel --name transaction --version 1.0 --sequence 1 --output json
peer lifecycle chaincode commit -o orderer.example.com:7050 --tls --cafile "$ORDERER_CA" \
  --channelID ledgerchannel --name transaction --version 1.0 --sequence 1 \
  --peerAddresses localhost:7051 --tlsRootCertFiles "$PWD/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" \
  --peerAddresses IP_KOMPUTER_B:9051 --tlsRootCertFiles "$PWD/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
```

Ulangi persis untuk chaincode asset.

### Langkah 7 - Buktikan datanya benar-benar tersebar

```sh
# di Komputer A: tulis satu transaksi lewat chaincode (sesuaikan argumen dengan fungsi
# chaincode transaction yang sebenarnya, lihat chaincode/transaction/)

# di Komputer B: query LANGSUNG ke peer B (bukan lewat aplikasi, bukan lewat Komputer A):
peer chaincode query -C ledgerchannel -n transaction -c "{\"Args\":[\"...\"]}"
```

Kalau query di Komputer B menampilkan data yang ditulis dari Komputer A, itu bukti konkret bahwa
Komputer B punya salinan ledger independennya sendiri - persis konsep "terdistribusi" yang
dibahas sebelumnya, sekarang benar-benar berjalan di dua mesin fisik.

### Langkah 8 - Sambungkan aplikasi (opsional, gabung dengan Bagian 1)

Kalau Bagian 1 juga dijalankan, arahkan ledger-api (di deploy/office) ke jaringan dua-komputer
ini: set FABRIC_ENABLED=true dan perbarui connection profile-nya supaya menunjuk
localhost:7051 / IP-Komputer-B:9051 alih-alih container Docker satu host. Ini konfigurasi, bukan
kode - persis Tahap 6 di ringkasan "cara aktifkan" yang sudah dibahas sebelumnya.

---

## Kalau macet

- peer channel fetch/join gagal, timeout: paling sering firewall (ulangi Langkah 3) atau
  extra_hosts salah IP (docker exec ... getent hosts orderer.example.com di Langkah 4 harus
  menunjukkan IP yang benar).
- TLS handshake error: pastikan folder yang disalin ke Komputer B itu utuh (ordererOrganizations/
  ikut tersalin, dipakai untuk verifikasi TLS orderer).
- docker.sock mount gagal di Windows: sesuaikan baris DOCKER_SOCK di file compose dengan apa
  yang dipakai bootstrap.sh yang sudah terbukti jalan di mesin itu (cek
  network/vendor/fabric-samples/test-network/network.sh, sekitar baris 496).
