#!/usr/bin/env python3
"""
IP-OSINT-PRO v1.0 - Advanced IP Address OSINT Tool
Created by: @Zaaxdisini__
GitHub: https://github.com/Zaaxdisini__/ip-osint-pro

Disclaimer: For authorized security testing and educational purposes only.
"""

import requests
import json
import sys
import time
import socket
import whois
import dns.resolver
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

# ============== BANNER ==============
BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
{Fore.CYAN}║{Fore.WHITE}  ██╗██████╗       ██████╗ ███████╗██╗███╗   ██╗████████╗{Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}  ██║██╔══██╗      ██╔══██╗██╔════╝██║████╗  ██║╚══██╔══╝{Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}  ██║██████╔╝█████╗██████╔╝███████╗██║██╔██╗ ██║   ██║   {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}  ██║██╔═══╝ ╚════╝██╔══██╗╚════██║██║██║╚██╗██║   ██║   {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}  ██║██║           ██████╔╝███████║██║██║ ╚████║   ██║   {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}  ╚═╝╚═╝           ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   {Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}          IP OSINT PRO - by @Zaaxdisini__{Fore.CYAN}              ║
{Fore.CYAN}║{Fore.YELLOW}       Nama • Umur • Medsos • Alamat • DNS • WHOIS{Fore.CYAN}       ║
{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Fore.RESET}
"""

# ============== KONFIGURASI API KEYS ==============
# Daftar gratis API - user bisa upgrade sendiri
API_KEYS = {
    "ipinfo": "",        # Gratis, 50k req/bulan
    "ipapi": "",         # Gratis, 1000 req/hari (daftar di ip-api.com)
    "abstractapi": "",   # Gratis, 1000 req/bulan (daftar di abstractapi.com)
    "shodan": "",        # Gratis limited (daftar di shodan.io)
}

# ============== FUNGSI UTAMA ==============

def print_section(title):
    """Print section header"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.YELLOW}[+] {title}")
    print(f"{Fore.CYAN}{'='*60}{Fore.RESET}")

def print_info(label, value, color=Fore.WHITE):
    """Print info with label"""
    print(f"{Fore.GREEN}[*] {label}: {color}{value}{Fore.RESET}")

def print_error(msg):
    """Print error message"""
    print(f"{Fore.RED}[!] {msg}{Fore.RESET}")

def print_success(msg):
    """Print success message"""
    print(f"{Fore.GREEN}[✓] {msg}{Fore.RESET}")

def get_public_ip():
    """Dapatkan IP publik sendiri"""
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=10)
        return r.json().get("ip", "Unknown")
    except:
        try:
            r = requests.get("https://httpbin.org/ip", timeout=10)
            return r.json().get("origin", "Unknown")
        except:
            return "Gagal mendapat IP"

def resolve_domain(domain):
    """Resolve domain ke IP"""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None

def reverse_dns(ip):
    """Reverse DNS lookup"""
    try:
        host = socket.gethostbyaddr(ip)
        return host[0]
    except:
        return "No PTR record"

def dns_records(domain):
    """Ambil berbagai DNS records"""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except:
            records[rtype] = []
    
    return records

def whois_lookup(target):
    """WHOIS lookup"""
    try:
        w = whois.whois(target)
        return {
            "org": w.org if hasattr(w, 'org') else "N/A",
            "country": w.country if hasattr(w, 'country') else "N/A",
            "city": w.city if hasattr(w, 'city') else "N/A",
            "address": w.address if hasattr(w, 'address') else "N/A",
            "name": w.name if hasattr(w, 'name') else "N/A",
            "email": w.emails if hasattr(w, 'emails') else "N/A",
            "phone": w.phone if hasattr(w, 'phone') else "N/A",
            "registrar": w.registrar if hasattr(w, 'registrar') else "N/A",
            "creation_date": str(w.creation_date) if hasattr(w, 'creation_date') else "N/A",
            "expiration_date": str(w.expiration_date) if hasattr(w, 'expiration_date') else "N/A",
        }
    except Exception as e:
        return {"error": str(e)}

def ipinfo_lookup(ip):
    """Menggunakan ipinfo.io API"""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=15)
        if r.status_code == 200:
            data = r.json()
            return {
                "ip": data.get("ip"),
                "hostname": data.get("hostname"),
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "loc": data.get("loc"),
                "org": data.get("org"),
                "postal": data.get("postal"),
                "timezone": data.get("timezone"),
            }
    except:
        return {}

def ipapi_lookup(ip):
    """Menggunakan ip-api.com (free, no API key needed)"""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=15)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return {
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "as": data.get("as"),
                    "asname": data.get("asname"),
                    "country": data.get("country"),
                    "countryCode": data.get("countryCode"),
                    "region": data.get("region"),
                    "regionName": data.get("regionName"),
                    "city": data.get("city"),
                    "zip": data.get("zip"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "mobile": data.get("mobile"),
                    "proxy": data.get("proxy"),
                    "hosting": data.get("hosting"),
                }
    except:
        return {}

def shodan_lookup(ip, api_key=""):
    """Shodan.io lookup (pake API key kalo ada)"""
    if not api_key:
        return {"note": "No Shodan API key configured"}
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=15)
        if r.status_code == 200:
            data = r.json()
            ports = data.get("ports", [])
            services = []
            for service in data.get("data", [])[:5]:
                services.append({
                    "port": service.get("port"),
                    "transport": service.get("transport"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                })
            return {
                "ports": ports,
                "services": services,
                "os": data.get("os"),
                "hostnames": data.get("hostnames"),
                "vulns": data.get("vulns", []),
            }
    except:
        return {}

def abuseipdb_lookup(ip):
    """Cek reputasi IP di AbuseIPDB (public endpoint)"""
    try:
        r = requests.get(f"https://www.abuseipdb.com/check/{ip}", 
                        headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        if r.status_code == 200 and "abuse-confidence-score" in r.text:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, 'html.parser')
            score_elem = soup.find("span", class_="abuse-confidence-score")
            if score_elem:
                return {"abuse_score": score_elem.text.strip()}
    except:
        pass
    return {}

def virustotal_lookup(ip):
    """Cek VirusTotal (public page)"""
    try:
        r = requests.get(f"https://www.virustotal.com/ui/ip_addresses/{ip}", 
                        headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
    except:
        return {}

def port_scan_fast(ip):
    """Quick scan port umum (non-intrusive)"""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                    445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 
                    5900, 5985, 5986, 6379, 8080, 8443, 9090, 27017]
    open_ports = []
    
    print(f"{Fore.YELLOW}[*] Scanning common ports...{Fore.RESET}")
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = socket.getservbyport(port) if port <= 65535 else "unknown"
                open_ports.append({"port": port, "service": service})
                print(f"{Fore.GREEN}    Port {port:5} open -> {service}{Fore.RESET}")
            sock.close()
        except:
            pass
    
    return open_ports

def social_media_check(username):
    """Cek username di berbagai platform sosial media"""
    platforms = {
        "Instagram": f"https://www.instagram.com/{username}/",
        "Twitter/X": f"https://twitter.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "GitHub": f"https://github.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Telegram": f"https://t.me/{username}",
        "Snapchat": f"https://www.snapchat.com/add/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Dev.to": f"https://dev.to/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Discord": f"https://discord.com/users/{username}",
    }
    
    found = []
    print(f"{Fore.YELLOW}[*] Checking social media for username: {username}{Fore.RESET}")
    
    for platform, url in platforms.items():
        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            if r.status_code == 200:
                found.append({"platform": platform, "url": url, "status": "Found"})
                print(f"{Fore.GREEN}    ✓ {platform}: {url}{Fore.RESET}")
            else:
                print(f"{Fore.RED}    ✗ {platform}: Not found{Fore.RESET}")
        except:
            print(f"{Fore.YELLOW}    ? {platform}: Error checking{Fore.RESET}")
    
    return found

def extract_emails_from_text(text):
    """Extract email addresses from text"""
    import re
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.findall(email_pattern, text)

def google_dorks(ip, domain=""):
    """Generate Google dorks untuk OSINT"""
    dorks = [
        f'site:{domain} "{ip}"',
        f'intitle:"{ip}"',
        f'inurl:{ip}',
        f'"{ip}" "admin" login',
        f'"{ip}" config filetype:txt',
        f'"{ip}" password filetype:log',
        f'"{ip}" "phone" OR "email" OR "contact"',
        f'"{ip}" "vulnerability" OR "exploit"',
    ]
    return dorks

# ============== MAIN ==============

def main():
    print(BANNER)
    
    # Parse argument
    if len(sys.argv) < 2:
        print(f"{Fore.YELLOW}Usage: python3 ip_osint_pro.py <IP_ADDRESS|DOMAIN>{Fore.RESET}")
        print(f"        python3 ip_osint_pro.py 8.8.8.8")
        print(f"        python3 ip_osint_pro.py example.com")
        print(f"        python3 ip_osint_pro.py --myip (cek IP sendiri)")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Cek IP sendiri
    if target.lower() == "--myip":
        my_ip = get_public_ip()
        print_section("IP PUBLIK ANDA")
        print_info("IP", my_ip, Fore.CYAN)
        target = my_ip
    
    # Resolve domain ke IP jika perlu
    original_target = target
    if not target.replace('.', '').isdigit():
        resolved = resolve_domain(target)
        if resolved:
            print_section("DOMAIN RESOLVE")
            print_info("Domain", target)
            print_info("Resolved IP", resolved, Fore.CYAN)
            target = resolved
        else:
            print_error(f"Tidak bisa resolve domain: {target}")
            sys.exit(1)
    
    print_section(f"IP TARGET: {target}")
    
    # ====== 1. IPINFO.IO ======
    print_section("IPINFO.IO - GEOLOKASI")
    ipinfo = ipinfo_lookup(target)
    if ipinfo:
        print_info("ISP/Org", ipinfo.get("org", "N/A"))
        print_info("Hostname", ipinfo.get("hostname", "N/A"))
        print_info("City", ipinfo.get("city", "N/A"))
        print_info("Region", ipinfo.get("region", "N/A"))
        print_info("Country", ipinfo.get("country", "N/A"))
        print_info("Location", ipinfo.get("loc", "N/A"))
        print_info("Postal Code", ipinfo.get("postal", "N/A"))
        print_info("Timezone", ipinfo.get("timezone", "N/A"))
    
    # ====== 2. IP-API.COM ======
    print_section("IP-API.COM - DETAIL LENGKAP")
    ipapi = ipapi_lookup(target)
    if ipapi:
        print_info("ISP", ipapi.get("isp", "N/A"))
        print_info("Organization", ipapi.get("org", "N/A"))
        print_info("AS Number", ipapi.get("as", "N/A"))
        print_info("AS Name", ipapi.get("asname", "N/A"))
        print_info("Country", f"{ipapi.get('country', 'N/A')} ({ipapi.get('countryCode', 'N/A')})")
        print_info("Region", ipapi.get("regionName", "N/A"))
        print_info("City", ipapi.get("city", "N/A"))
        print_info("ZIP Code", ipapi.get("zip", "N/A"))
        print_info("Coordinates", f"{ipapi.get('lat', 'N/A')}, {ipapi.get('lon', 'N/A')}")
        print_info("Timezone", ipapi.get("timezone", "N/A"))
        print_info("Is Mobile?", "Yes" if ipapi.get("mobile") else "No")
        print_info("Is Proxy/VPN?", "Yes" if ipapi.get("proxy") else "No")
        print_info("Is Hosting?", "Yes" if ipapi.get("hosting") else "No")
    
    # ====== 3. REVERSE DNS ======
    print_section("REVERSE DNS")
    rdns = reverse_dns(target)
    print_info("PTR Record", rdns, Fore.CYAN)
    
    # ====== 4. WHOIS LOOKUP ======
    print_section("WHOIS LOOKUP")
    whois_data = whois_lookup(original_target if not original_target.replace('.','').isdigit() else target)
    if "error" not in whois_data:
        for key, value in whois_data.items():
            if value and value != "N/A":
                print_info(key.replace("_", " ").title(), str(value)[:100], Fore.CYAN)
    else:
        print_info("WHOIS", whois_data.get("error", "Error"))
    
    # ====== 5. DNS RECORDS (jika domain) ======
    if not original_target.replace('.', '').isdigit():
        print_section("DNS RECORDS")
        dns_data = dns_records(original_target)
        for rtype, records in dns_data.items():
            if records:
                print_info(f"{rtype} Records", ", ".join(records[:3]), Fore.CYAN)
    
    # ====== 6. PORT SCAN ======
    print_section("PORT SCAN (COMMON PORTS)")
    ports = port_scan_fast(target)
    if ports:
        print_success(f"Ditemukan {len(ports)} port terbuka")
        for p in ports:
            print_info(f"Port {p['port']}", p['service'], Fore.GREEN)
    else:
        print_info("Hasil", "Tidak ada port umum yang terbuka atau timeout")
    
    # ====== 7. SHODAN ======
    print_section("SHODAN.IO - DEVICE INTEL")
    shodan = shodan_lookup(target, API_KEYS.get("shodan", ""))
    if "note" not in shodan:
        if shodan.get("ports"):
            print_info("Open Ports", ", ".join(map(str, shodan["ports"])))
        if shodan.get("os"):
            print_info("OS", shodan["os"])
        if shodan.get("hostnames"):
            print_info("Hostnames", ", ".join(shodan["hostnames"]))
        if shodan.get("vulns"):
            print_info("Vulnerabilities", ", ".join(shodan["vulns"]))
    else:
        print_info("Shodan", shodan["note"])
        print(f"{Fore.YELLOW}     Daftar gratis di https://www.shodan.io untuk API key{Fore.RESET}")
    
    # ====== 8. VIRUSTOTAL ======
    print_section("VIRUSTOTAL - REPUTASI")
    vt = virustotal_lookup(target)
    if vt:
        print_info("Malicious", vt.get("malicious", 0), Fore.RED)
        print_info("Suspicious", vt.get("suspicious", 0), Fore.YELLOW)
        print_info("Harmless", vt.get("harmless", 0), Fore.GREEN)
        print_info("Undetected", vt.get("undetected", 0))
    
    # ====== 9. SOCIAL MEDIA CHECK ======
    print_section("SOCIAL MEDIA CHECK")
    # Extract potential username dari WHOIS atau hostname
    potential_username = None
    if "name" in whois_data and whois_data["name"] != "N/A":
        potential_username = str(whois_data["name"]).split()[0].lower()
    
    if potential_username:
        print_info("Checking username from WHOIS", potential_username)
        medsos_results = social_media_check(potential_username)
    
    # Coba dari hostname juga
    hostname_part = ipinfo.get("hostname", "")
    if hostname_part and hostname_part != "N/A":
        username_hint = hostname_part.split(".")[0]
        if username_hint and username_hint != potential_username:
            print_info("Checking username from hostname", username_hint)
            medsos_results2 = social_media_check(username_hint)
    
    # ====== 10. GOOGLE DORKS ======
    print_section("GOOGLE DORKS UNTUK OSINT")
    domain = original_target if not original_target.replace('.','').isdigit() else ""
    dorks = google_dorks(target, domain)
    for i, dork in enumerate(dorks, 1):
        search_url = f"https://www.google.com/search?q={dork.replace(' ', '+')}"
        print(f"{Fore.YELLOW}[Dork {i}] {Fore.CYAN}{dork}{Fore.RESET}")
        print(f"{Fore.GREEN}    -> {search_url}{Fore.RESET}")
        print()
    
    # ====== 11. SUMMARY ======
    print_section("SUMMARY / RINGKASAN")
    
    summary_data = {
        "Target IP": target,
        "ISP/Org": ipinfo.get("org", ipapi.get("isp", "N/A")),
        "Lokasi": f"{ipapi.get('city', 'N/A')}, {ipapi.get('regionName', 'N/A')}, {ipapi.get('country', 'N/A')}",
        "Koordinat": f"{ipapi.get('lat', 'N/A')}, {ipapi.get('lon', 'N/A')}",
        "Timezone": ipapi.get("timezone", "N/A"),
        "Reverse DNS": rdns,
        "Port Terbuka": len(ports),
        "Abuse Reports": "Check AbuseIPDB",
        "VT Malicious": vt.get("malicious", "N/A"),
        "Proxy/VPN": "Ya" if ipapi.get("proxy") else "Tidak",
        "Hosting": "Ya" if ipapi.get("hosting") else "Tidak",
    }
    
    for label, value in summary_data.items():
        print_info(label, str(value), Fore.CYAN)
    
    # ====== EXPORT JSON ======
    print_section("EXPORT DATA")
    
    full_data = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "scanner": "@Zaaxdisini__ IP-OSINT-PRO",
        "ipinfo": ipinfo,
        "ipapi": ipapi,
        "reverse_dns": rdns,
        "whois": whois_data,
        "ports": ports,
        "shodan": shodan,
        "virustotal": vt,
    }
    
    # Simpan ke file
    filename = f"osint_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(full_data, f, indent=2, default=str)
    
    print_success(f"Data lengkap disimpan ke: {filename}")
    print(f"\n{Fore.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"{Fore.GREEN}  IP OSINT PRO by @Zaaxdisini__")
    print(f"{Fore.GREEN}  GitHub: https://github.com/Zaaxdisini__/ip-osint-pro")
    print(f"{Fore.YELLOW}  Tools ini untuk educational & authorized testing only!")
    print(f"{Fore.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Fore.RESET}")

if __name__ == "__main__":
    main()
