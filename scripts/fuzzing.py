from scapy.all import *

ip = IP(dst="postgres_server")
tcp = TCP(sport=RandShort(), dport=5432, flags="PA")
raw = Raw(load=RandString(size=40))

packet = ip/tcp/raw
send(packet, verbose=False)

print("Fuzzing packet enviado.")
