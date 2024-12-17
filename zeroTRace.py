import concurrent
import csv
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import pyfiglet
from urllib.parse import urlparse
from scapy.all import *

print("""                               .=%@@@+.
                           .-@@@@@@@@@@@@+.
                      .-*%#@@@@@@@*+#%@@@@@@@*-.
               .:+#%@@%%@@@@@@@@@@%@@@@@@@@@@@*@@@%#+-.
       .#@@@@@@@@@#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#
       .%@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
       .%@@@@@@@@@@@#%@@@@@@@@@@@@@@@@@@@@@@@@@@@%%@@@@@@@@%**.
       .*@@@@@@@@@@#@%@@@@@@@@@%@@@@@@@@%*@@@@@@@@@@@@@@@@@@@#
        *@@@@@@@@#@@@@%@@@@@@@@@@@@@@@@@%%@@@@@@@@@@@@@@@@@@@*
        =@@@@@@#@@@@@@@@%@@@@@@@@@@@@@@@*@@@@@@@@@@#@@@@@@@@@+
        -@@@@@%@@@@@@@@@@%@@@@@@@@@@@@@@*@@@@@@@@@@@%@@@@@@@@-
        :@@@#@@@@@@@@@@@@@%@@@@@@@@@@@@@#@@@@@@@@@@%*#@@@@@@%:
         @@#@@@@@@@@@@@@@@@@*@@@@@@@@@@@%@@@@%@@@@@@@@@@@@@@@.
         *%@@@@@@@@#%@@@@@@@@%=.      .=*@@@@@@@@@@@@@@@@@@@@.
         %@@@@@@@@@%%@@@@@@%.  __ _ _  _   %@@@@@@@@@@@@@@@@@.
         +@@@@@@@@#@@@@@@@*     /|_|_>/ \    +@@@@@@@@@@@@@@*
         .@@@@@@@#@@@@@@@%.    /_|_|\ \_/    .%@@@@@@@@@@@@@.
          *@@@@@%@@@@@@@@  ___ _  _   _ _   :*%@%%#*+*#@@@#
          :@@@%@@@@@@@@@%   | |_>/_\ / |_   :@@@@@@@@@#@@@:
           +@#@@@@@@@@@*@   | |\/   \\\_|_    %@@@@@@%%@@@#
           -#@@@@@@@@@%@@@+                  #@@@@@@@#@@@@.
            :@@@@@@@@%@@@@@%.                :%@@@@@@#@@@-
            .+@@@@@@#@@@@@@@@@*=      .*#=.:   .+@@@@*#@+.
              #@@@%%@@@@@@@@@@%@@@@@@@@@@@@@@#.   :%@@@%.
               *##@@@@@@@@@@@#@@@@@@@@@@@@@@@@@@=   .=#
                +@@#+#@@@@@@*@@@@@@@@@@@@@@@@@@@@@@.
                 -@@@@@@@#*%@@@@@@@@@@@@@@@@@@@@@@@@=
                  .@@@@@@@@@@@@@@@@@@@@%@@@@%#*##@@:
                    #@@@@@@@@@@@@@@@@@@@@@@@@@@@@%.
                     :@@@@@@@@@@@@@@@@@@@@@@@@@@-
                      .-@@@@@@@@@@@@@@@@@@@@@@=.
                         =@@@@@@@@@@@@@@@@@@+.
                           -@@@@@@@@@@@@@@=
                             .%@@@%@@@@@.
                                -#@@#-
                                                                      """)

def validate_ws(website):
    try:
        result = urlparse(website)
        return all([result.scheme, result.netloc])
    except AttributeError:
        return False

def validate_ip(ip_str):
   try:
       ipaddress.ip_address(ip_str)
       return True
   except ValueError:
       return False

def input_trg(target):
    print("\n" + 50 * "-")
    print("\nScanning Target: " + target)
    print("Scanning Started At: " + str(datetime.now()) + "\n")
    print(50 * "-")

# Port Scanning
def process_trg(target, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(5)
    try:
        # Return the open port
        result = s.connect_ex((target, port))
        if result == 0:
            s.close()
            return True
        else:
            return False
    except KeyboardInterrupt:
        print("\n Exiting :(")
        sys.exit()
    except socket.error:
        print("[-] Host is not responding :(")
        sys.exit()

def process_packet(packet, packets):
    print(packet.summary())
    packets.append(packet)
    with open("packet_log.txt", "a") as log:
            log.write(packet.show(dump=True))    #dump=True To Get A String
            log.write("\n\n####################################################################\n\n")

def menu():
    print("\n")
    print("Welcome To ZeroTRace")
    print("1) Port Scanning")
    print("2) Network Packet Sniffing")
    print("3) Exit")

def port_scanning():
    while True:
        scan_address = str(input("Please Enter An IP Address / Domain > ")).strip()
        if(len(scan_address) == 0):
            print("[-] Address Should Not Be Empty.")
            continue
        elif not(validate_ip(scan_address) or validate_ws(scan_address)):
            print("[-] Invalid IP Address Or Websites ONLY IP Address And Websites Is Accepted")
            continue
        else:
            break

    while True:
        output_file_name = str(input("Please Enter A File Name For Output Solution > ")).strip()
        if(output_file_name[-4:].lower() != ".csv"):
            print("[-] Invalid File Type ONLY csv File Is Accepted")
            continue
        else:
            break

    # print banner
    input_trg(scan_address)

    # Open a spreadsheet
    spreadsheet = csv.writer(open(output_file_name, 'w'), delimiter = ',')
    spreadsheet.writerow(['Target', 'Port', 'Status', 'Datetime'])

    # Scanning port
    with ThreadPoolExecutor(max_workers = 128) as executor:
        future_result = {executor.submit(process_trg, scan_address, port): port for port in range(1, 65536)}
        for future in concurrent.futures.as_completed(future_result):
            port = future_result[future]
            try:
                connected = future.result()
                try:
                    spreadsheet.writerow([
                        scan_address,
                        str(port),
                        str(connected),
                        str(datetime.now())])
                except Exception as e:
                    print('[-] Error Writing To Spreadsheet. %s' % e)
                if connected:
                    print("[+] %d Connected" % port)
            except Exception as e:
                print('[-] Error Pulling Result From Future. %s' % e)

def packet_sniffing():
    # Scan NIC
    interface = get_if_list()
    print("Network Interface Card:")
    i = 0
    for i, iface in enumerate(interface):
        print(f"{i + 1}) {iface}")
    # Select NIC
    while True:
        try:
            int_index = int(input("Please Select A Network Interface Card For Sniffing ："))
            if (int_index <= 0 or int_index > i + 1):
                print("[-] Invalid Input. Please Enter A Valid Number.")
                continue
            else:
                break
        except ValueError:
            print("[-] Invalid Input. Please Enter A Valid Number.")

    int_selected = interface[int_index - 1]

    # Filtering
    print("\nPlease Select A Filter Option : ")
    print("1) Don't Apply Filter.")
    print("2) Filter Via IP Address.")
    print("3) Filter Via Protocol.")
    print("4) Filter Via IP Address and Protocol.\n")

    while True:
        try:
            filter_option = int(input("> "))
            if (filter_option <= 0 or filter_option >= 5):
                print("[-] Invalid Input. Please Enter A Valid Number.")
                continue
            if (filter_option == 1):
                break
            if (filter_option == 3 or filter_option == 4):
                print("Default Protocol Selection : tcp, udp, icmp")
                print("Specified Protocol Selection : tcp port {port_number}")
                filter_protocol = str(input("Please Enter The Protocol That Want To Filter : ")).strip()
                if (filter_option == 4):
                    pass
                else:
                    break
            if (filter_option == 2 or filter_option == 4):
                filter_src_address = str(input("Please Enter The Source IP Address That Want To Filter (If No Then Leave It Empty And Press Enter) : ")).strip()
                filter_dest_address = str(input("Please Enter The Destination IP Address That Want To Filter (If No Then Leave It Empty And Press Enter) : ")).strip()
                break
        except ValueError:
            print("[-] Invalid Input. Please Enter A Valid Number.")
            continue

    # Get NIC IP Address and MAC Address
    host_ip = get_if_addr(int_selected)
    host_mac = get_if_hwaddr(int_selected)

    # Sniffing
    packets = []

    print("\n")
    print("Selected Interface : " + int_selected)
    print("IP Address : " + host_ip)
    print("MAC Address : " + host_mac)
    print("Start Sniffing......(Ctrl + C To Quit Sniffing)")

    try:
        filter_string = ""
        if (filter_option == 2 or filter_option == 4):
            filter_conditions = []
            if filter_src_address:
                filter_conditions.append(f"src host {filter_src_address}")
            if filter_dest_address:
                filter_conditions.append(f"dst host {filter_dest_address}")
            filter_string += " and ".join(filter_conditions)

        # The Protocol Only Support tcp, udp, icmp
        # If Want To Use The Specified Protocol : tcp port {port number}
        if (filter_option == 3 or filter_option == 4):
            if filter_protocol:
                if filter_string:
                    filter_string += " and "
                filter_string += filter_protocol.lower()

        print(f"Using filter: {filter_string}")

        if filter_string:
            sniff(iface=int_selected, prn=lambda pkt: process_packet(pkt, packets), filter=filter_string)
        else:
            sniff(iface=int_selected, prn=lambda pkt: process_packet(pkt, packets))

    except KeyboardInterrupt:
        print("[+] Sniffing Stopped. Saving Packets To 'packet_log.cap' and 'packet_log.txt' File......\n")

    wrpcap("packet_log.cap", packets)
    print("\n[+] Packets Saved To 'packet_log.cap' and 'packet_log.txt' File.")

# Main
flag = ""
while True:
    menu()
    try:
        user_input = int(input("Please Enter > "))
        if (user_input <= 0 or user_input >= 4):
            print("[-] Invalid Number. Please Enter Number Between 1 - 3.")
            continue
        else:
            if (user_input == 3):
                print("[+] Thanks For Using.")
                sys.exit()
            elif (user_input == 1):
                port_scanning()
            elif (user_input == 2):
                packet_sniffing()

            # Continue Or Not
            flag = str(input("Do You Want To Continue? (Yes/No) > "))
            if (flag.lower() == "yes" or flag.lower() == "y"):
                continue
            elif (flag.lower() == "no" or flag.lower() == "n"):
                print("[+] Thanks For Using.")
                sys.exit()
            else:
                print("[-] Invalid Strings. Auto Quit.")
                sys.exit()
                
    except ValueError:
        print("[-] Please Enter A Valid Number.")
        continue
             