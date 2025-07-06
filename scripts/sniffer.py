from scapy.all import *

def packet_callback(pkt):
    print("---- Paquete capturado ----")
    print(pkt.summary())

sniff(iface="eth0", filter="tcp port 5432", prn=packet_callback, store=0)
