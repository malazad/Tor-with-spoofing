import socket
import time
from scapy.all import *

client_ip = '137.48.184.170'
client_port = 1111


guard_port = 4567

serversocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serversocket.bind(('', guard_port))
'''
These packets will create a hole on the firewall of the 2nd guard node 
so that packets from the client can reach to the 2nd guard node. 
'''
serversocket.sendto(b'Hello client', (client_ip, client_port))
receive, _ = serversocket.recvfrom(1024)
spoof_src_ip = receive.decode("utf-8")

'''
The 2nd guard node will respond with a random port which will be used to receive the 
spoofed packets at the 2nd guard node. 
'''
spoof_dst_port = 3333
serversocket.sendto(b'3333', (client_ip, client_port))

print(spoof_src_ip)

receive, _ = serversocket.recvfrom(1024)
spoof_src_port = int(receive.decode("utf-8"))
print(spoof_src_port)



buffer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
buffer.bind(('', spoof_dst_port))

'''
These packets will create a hole on the firewall of the 2nd guard node 
so that packets from the onion server with the spoofed src IP address
can reach to the 2nd guard node. 
'''
buffer.sendto(b'Hello server', (spoof_src_ip, spoof_src_port))
buffer.sendto(b'Hello server2', (spoof_src_ip, spoof_src_port))
buffer.sendto(b'Hello server3', (spoof_src_ip, spoof_src_port))
buffer_packet = ''
start = time.time()
count = 0

ss = conf.L3socket()
while(buffer_packet!=b'EOF'):
    end = time.time()
    count += 1
    if end - start > 1:
        start = time.time()
        buffer.sendto(b'Hello server3', (spoof_src_ip, spoof_src_port))
        print('Receiving......' + str(count))
    buffer_packet, _ = buffer.recvfrom(1040)
    serversocket.sendto(buffer_packet, (client_ip, client_port))

print("Receiving Done " + str(count))
buffer.close()
serversocket.close()

