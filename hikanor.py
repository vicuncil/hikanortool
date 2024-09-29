import socket
import hashlib
import whois
import os
import time
import random
from scapy.all import ARP, Ether, srp
from tabulate import tabulate
from colorama import Fore, init
import sys

init(autoreset=True)
hashes_dict = {
    "5d41402abc4b2a76b9719d911017c592": "hello", 
    "098f6bcd4621d373cade4e832627b4f6": "test",  
}

time.sleep(2)
def print_gradient_text(text):
    length = len(text)
    for i in range(length):
        b = int(255 - (255 - 230) * i / length)
        g = int(0 + (216 - 0) * i / length)
        r = int(0 + (173 - 0) * i / length)
        color_code = f'\033[38;2;{r};{g};{b}m'
        sys.stdout.write(color_code + text[i])
        sys.stdout.flush()
    sys.stdout.write('\033[0m')  

titles = ["""

   ▄█    █▄     ▄█     ▄█   ▄█▄    ▄████████ ███▄▄▄▄    ▄██████▄     ▄████████ 
  ███    ███   ███    ███ ▄███▀   ███    ███ ███▀▀▀██▄ ███    ███   ███    ███ 
  ███    ███   ███▌   ███▐██▀     ███    ███ ███   ███ ███    ███   ███    ███ 
 ▄███▄▄▄▄███▄▄ ███▌  ▄█████▀      ███    ███ ███   ███ ███    ███  ▄███▄▄▄▄██▀ 
▀▀███▀▀▀▀███▀  ███▌ ▀▀█████▄    ▀███████████ ███   ███ ███    ███ ▀▀███▀▀▀▀▀   
  ███    ███   ███    ███▐██▄     ███    ███ ███   ███ ███    ███ ▀███████████ 
  ███    ███   ███    ███ ▀███▄   ███    ███ ███   ███ ███    ███   ███    ███ 
  ███    █▀    █▀     ███   ▀█▀   ███    █▀   ▀█   █▀   ▀██████▀    ███    ███ 
                      ▀                                             ███    ███                            
                                    
                                                            discord.gg/QS5PnqsZ
""",
"""                                                                                   
        ,--,               ,--.                        ,--.    ,----..               
      ,--.'|   ,---,   ,--/  /|   ,---,              ,--.'|   /   /   \  ,-.----.    
   ,--,  | :,`--.' |,---,': / '  '  .' \         ,--,:  : |  /   .     : \    /  \   
,---.'|  : '|   :  ::   : '/ /  /  ;    '.    ,`--.'`|  ' : .   /   ;.  \;   :    \  
|   | : _' |:   |  '|   '   ,  :  :       \   |   :  :  | |.   ;   /  ` ;|   | .\ :  
:   : |.'  ||   :  |'   |  /   :  |   /\   \  :   |   \ | :;   |  ; \ ; |.   : |: |  
|   ' '  ; :'   '  ;|   ;  ;   |  :  ' ;.   : |   : '  '; ||   :  | ; | '|   |  \ :  
'   |  .'. ||   |  |:   '   \  |  |  ;/  \   \'   ' ;.    ;.   |  ' ' ' :|   : .  /  
|   | :  | ''   :  ;|   |    ' '  :  | \  \ ,'|   | | \   |'   ;  \; /  |;   | |  \  
'   : |  : ;|   |  ''   : |.  \|  |  '  '--'  '   : |  ; .' \   \  ',  / |   | ;\  \ 
|   | '  ,/ '   :  ||   | '_\.'|  :  :        |   | '`--'    ;   :    /  :   ' | \.' 
;   : ;--'  ;   |.' '   : |    |  | ,'        '   : |         \   \ .'   :   : :-'   
|   ,/      '---'   ;   |,'    `--''          ;   |.'          `---`     |   |.'     
'---'               '---'                     '---'                      `---'       

                                                                discord.gg/QS5PnqsZ                                                                                    
""",
""" 
 ,--.-,,-,--, .=-.-.,--.-.,-.    ,---.      .-._          _,.---._                 
/==/  /|=|  |/==/_ /==/- |\  \ .--.'  \    /==/ \  .-._ ,-.' , -  `.   .-.,.---.   
|==|_ ||=|, |==|, ||==|_ `/_ / \==\-/\ \   |==|, \/ /, /==/_,  ,  - \ /==/  `   \  
|==| ,|/=| _|==|  ||==| ,   /  /==/-|_\ |  |==|-  \|  |==|   .=.     |==|-, .=., | 
|==|- `-' _ |==|- ||==|-  .|   \==\,   - \ |==| ,  | -|==|_ : ;=:  - |==|   '='  / 
|==|  _     |==| ,||==| _ , \  /==/ -   ,| |==| -   _ |==| , '='     |==|- ,   .'  
|==|   .-. ,\==|- |/==/  '\  |/==/-  /\ - \|==|  /\ , |\==\ -    ,_ /|==|_  . ,'.  
/==/, //=/  /==/. /\==\ /\=\.'\==\ _.\=\.-'/==/, | |- | '.='. -   .' /==/  /\ ,  ) 
`--`-' `-`--`--`-`  `--`       `--`        `--`./  `--`   `--`--''   `--`-`--`--'  
                                                         
                                                              discord.gg/QS5PnqsZ
""",
""" 

██   ██ ██ ██   ██  █████  ███    ██  ██████  ██████  
██   ██ ██ ██  ██  ██   ██ ████   ██ ██    ██ ██   ██ 
███████ ██ █████   ███████ ██ ██  ██ ██    ██ ██████  
██   ██ ██ ██  ██  ██   ██ ██  ██ ██ ██    ██ ██   ██ 
██   ██ ██ ██   ██ ██   ██ ██   ████  ██████  ██   ██ 
                                                      
                                  discord.gg/QS5PnqsZ       
""",
""" 

 ██░ ██  ██▓ ██ ▄█▀▄▄▄       ███▄    █  ▒█████   ██▀███  
▓██░ ██▒▓██▒ ██▄█▒▒████▄     ██ ▀█   █ ▒██▒  ██▒▓██ ▒ ██▒
▒██▀▀██░▒██▒▓███▄░▒██  ▀█▄  ▓██  ▀█ ██▒▒██░  ██▒▓██ ░▄█ ▒
░▓█ ░██ ░██░▓██ █▄░██▄▄▄▄██ ▓██▒  ▐▌██▒▒██   ██░▒██▀▀█▄  
░▓█▒░██▓░██░▒██▒ █▄▓█   ▓██▒▒██░   ▓██░░ ████▓▒░░██▓ ▒██▒
 ▒ ░░▒░▒░▓  ▒ ▒▒ ▓▒▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░
 ▒ ░▒░ ░ ▒ ░░ ░▒ ▒░ ▒   ▒▒ ░░ ░░   ░ ▒░  ░ ▒ ▒░   ░▒ ░ ▒░
 ░  ░░ ░ ▒ ░░ ░░ ░  ░   ▒      ░   ░ ░ ░ ░ ░ ▒    ░░   ░ 
 ░  ░  ░ ░  ░  ░        ░  ░         ░     ░ ░     ░     
                                     
                                     discord.gg/QS5PnqsZ                     
""",
""" 
██╗  ██╗██╗██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ██████╗ 
██║  ██║██║██║ ██╔╝██╔══██╗████╗  ██║██╔═══██╗██╔══██╗
███████║██║█████╔╝ ███████║██╔██╗ ██║██║   ██║██████╔╝
██╔══██║██║██╔═██╗ ██╔══██║██║╚██╗██║██║   ██║██╔══██╗
██║  ██║██║██║  ██╗██║  ██║██║ ╚████║╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝

                                   discord.gg/QS5PnqsZ
""",
""" 
=====================================================================
=  ====  ==    ==  ====  =====  =====  =======  ====    ====       ==
=  ====  ===  ===  ===  =====    ====   ======  ===  ==  ===  ====  =
=  ====  ===  ===  ==  =====  ==  ===    =====  ==  ====  ==  ====  =
=  ====  ===  ===  =  =====  ====  ==  ==  ===  ==  ====  ==  ===   =
=        ===  ===     =====  ====  ==  ===  ==  ==  ====  ==      ===
=  ====  ===  ===  ==  ====        ==  ====  =  ==  ====  ==  ====  =
=  ====  ===  ===  ===  ===  ====  ==  =====    ==  ====  ==  ====  =
=  ====  ===  ===  ====  ==  ====  ==  ======   ===  ==  ===  ====  =
=  ====  ==    ==  ====  ==  ====  ==  =======  ====    ====  ====  =
=====================================================================
  
                                                  discord.gg/QS5PnqsZ
"""
]
selected_title = random.choice(titles)
print_gradient_text(selected_title)


def dehash(hash_value):
    if hash_value in hashes_dict:
        print(f"Original text for hash {hash_value} is: {hashes_dict[hash_value]}")
    else:
        print(f"Not hash text found: {hash_value}")

def port_scan(target, ports):
    print(f"Scan on {target} to ports: {ports}")
    result_list = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target, port))
        status = "OPEN" if result == 0 else "CLOSED"
        result_list.append([port, status])
        sock.close()
    print(tabulate(result_list, headers=["Port", "Status"], tablefmt="pretty"))

def dns_lookup(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(tabulate([[domain, ip_address]], headers=["Domain", "IP Address"], tablefmt="pretty"))
    except Exception as e:
        print(f"Error gething DNS Lookup: {e}")

def traceroute(host):
    result = os.popen(f"traceroute {host}").read()
    print(f"\nTrace to {host}:\n{result}")

def arp_scan(ip_range):
    print(f"Scanning on {ip_range} for active device:")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append([received.psrc, received.hwsrc])
    print(tabulate(devices, headers=["IP Address", "MAC Address"], tablefmt="pretty"))

def hash_text(text):
    md5_hash = hashlib.md5(text.encode()).hexdigest()
    sha256_hash = hashlib.sha256(text.encode()).hexdigest()
    hash_table = [["MD5", md5_hash], ["SHA256", sha256_hash]]
    print(tabulate(hash_table, headers=["Algoriritm", "Hash"], tablefmt="pretty"))

def whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        whois_table = [
            ["Domain", domain],
            ["Regist", domain_info.registrar],
            ["Created on", domain_info.creation_date],
            ["Valide to", domain_info.expiration_date],
            ["Name of service", domain_info.name_servers]
        ]
        print(tabulate(whois_table, headers=["Atribute", "Information"], tablefmt="pretty"))
    except Exception as e:
        print(f"Error gethering WHOIS Information: {e}")

def ping_host(host):
    response = os.system(f"ping -c 4 {host}")
    if response == 0:
        print(f"{host} is active.")
    else:
        print(f"{host} not response")

def main():
    
    while True:
        print("")
        print("[1] Scan port")
        print("[2] Hashing text(MD5 и SHA256)")
        print("[3] Dehash MD5")
        print("[4] Whois information")
        print("[5] Ping to host")
        print("[6] DNS Lookup")
        print("[7] Traceroute")
        print("[8] ARP scan")
        print("[9] exit")

        choice = input("Chose options: ")

        if choice == '1':
            target = input("Enter ip address or domain: ")
            ports = input("Enter the ports for scan (example: 20 , 25 , 80 ,): ")
            port_list = list(map(int, ports.split(',')))
            port_scan(target, port_list)
        
        elif choice == '2':
            text = input("Enter text for hashing: ")
            hash_text(text)
        
        elif choice == '3':
            hash_value = input("Enter MD5 hash for dehash: ")
            dehash(hash_value)
        
        elif choice == '4':
            domain = input("Enter the domain for WHOIS: ")
            whois_info(domain)
        
        elif choice == '5':
            host = input("Enter ip address or domain for ping: ")
            ping_host(host)
        
        elif choice == '6':
            domain = input("Enter domain for DNS Lookup: ")
            dns_lookup(domain)
        
        elif choice == '7':
            host = input("Enter host for Traceroute: ")
            traceroute(host)
        
        elif choice == '8':
            ip_range = input("Enter ip address range for ARP scan (example: 192.168.1.0/24): ")
            arp_scan(ip_range)
        
        elif choice == '9':
            print("Exit")
            break
        
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()
