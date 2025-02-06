# Özellikler

* **Pasif keşif** için kullanılan servisler:
  - CertSpotter
  - crt.sh
  - HackerTarget
* **Aktif alt alan adı brute-force** taraması
* **Eşzamanlı tarama** (özelleştirilebilir iş parçacığı sayısı)
* **JSON çıktı formatı**
* **Özelleştirilebilir DNS çözümleyici**
* **Özel User-Agent desteği**
* **Sonuçları kaydetme özelliği**

#  Kurulum
```bash
# / Depoyu klonlayın
git clone https://github.com/rasperon/knock-go.git
cd knock-go

# Bağımlılıkları yükleyin
go mod download

# İkili dosyayı oluşturun
go build -o knock-go
```

# Kullanım
```
 ./knock-go:
  -bruteforce
        Perform subdomain bruteforce
  -dns string
        Custom DNS server (default "8.8.8.8:53")
  -domain string
        Domain to analyze
  -recon
        Perform subdomain reconnaissance
  -save string
        Folder to save results
  -threads int
        Number of concurrent threads (default 10)
  -timeout int
        Timeout in seconds (default 3)
  -useragent string
        Custom User-Agent
  -wordlist string
        Custom wordlist file
```
```bash
./knock-go -domain example.com -recon
./knock-go -domain example.com -bruteforce
./knock-go -domain example.com -recon -bruteforce -threads 20 -timeout 5 -dns 1.1.1.1:53 -save results
```
# Çıktı
Araç, çıktıyı JSON formatında üretir ve -save seçeneği kullanıldığında dosyaya kaydeder. Çıktı aşağıdaki bilgileri içerir:

    Alt alan adı
    Kaynak
    Tarama türü (Pasif/Bruteforce)

#  Sorumluluk Reddi
Bu araç yalnızca eğitim ve etik hackleme amaçları için tasarlanmıştır. Sorumlu bir şekilde kullanın ve yalnızca test etme izniniz olan sistemlerde kullanın. Ben, bu aracın herhangi bir kötüye kullanımından sorumlu değilimdir.

# Katkıda bulunma
Katkılar memnuniyetle karşılanır! Lütfen hata düzeltmeleri, iyileştirmeler veya yeni özelliklerle ilgili çekme istekleri gönderin.

# Lisans
[GPU Lisansı](LICENSE)