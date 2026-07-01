# OSINT BY MR ZX 
Osint adalah alat pelacak yang menargetkan ip target dan untuk ip kasih saja korban phising , dan ambil ip nya.

# CARA PASANG NYA 
pkg update && pkg upgrade
pkg install python git
git clone https://github.com/zaaxscond-arch/OSINT-IP.git
cd OSINT-IP
pip install requests colorama python-whois dnspython beautifulsoup4
python ip_osint_pro.py --myip
