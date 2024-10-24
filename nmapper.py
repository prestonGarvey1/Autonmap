import netifaces
import nmap
from termcolor import colored, cprint
#Definitions
Gateways = netifaces.gateways()
default_gateway = Gateways['default'][netifaces.AF_INET][0]

nm = nmap.PortScanner()

#Menu and Options
cprint("""
      --------------------------------------------
      | option 1: Scan your Router for open ports|
      | option 2: Scan a specific IP             |
      | option 3: Exit Program                   |
      --------------------------------------------
       """, 
       #Color Settings
"red", attrs=["bold"]
    
)
optioninput = input("option: ")
if optioninput == "1":
    print("Scanning host IP", default_gateway,"...")
    nm.scan(hosts=default_gateway, arguments=' -p 1-1024')

# Print scan results
    print(f"Scan results for {default_gateway}:")
    for host in nm.all_hosts():
        print(f"Host : {host} ({nm[host].hostname()})")
        print(f"State : {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"Protocol : {proto}")
            lport = nm[host][proto].keys()
            for port in lport:
                print(f"port : {port}\tstate : {nm[host][proto][port]['state']}")
    print("Scanning finished! Press enter to exit...")
elif optioninput == "2":
    print("What IP would you like to scan?")
    scannedip = input()
    print("Scanning IP...")
    nm.scan(hosts=scannedip, arguments='-p 1-1024')

    # Print scan results
    print(f"Scan results for {scannedip}:")
    for host in nm.all_hosts():
        print(f"Host : {host} ({nm[host].hostname()})")
        print(f"State : {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"Protocol : {proto}")
            lport = nm[host][proto].keys()
            for port in lport:
                print(f"port : {port}\tstate : {nm[host][proto][port]['state']}")
        

 
elif optioninput == 3: 
    print("Exiting Program!")
    exit()



    # Print scan results
    print(f"Scan results for {scannedip}:")
    for host in nm.all_hosts():
        print(f"Host : {host} ({nm[host].hostname()})")
        print(f"State : {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"Protocol : {proto}")
            lport = nm[host][proto].keys()
            for port in lport:
                print(f"port : {port}\tstate : {nm[host][proto][port]['state']}")
        
        
elif optioninput == 3: 
    print("Exiting Program!")
    exit()

