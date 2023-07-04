import requests
import json
import time
import re
import socket
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES



#blocklist = []
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

total = 102400
'''
packets_per_block = 4 * 1024
a = '0b' + '1' * packets_per_block

for i in range(int(total/packets_per_block)):
    blocklist.append(int(a,2))
'''
guard_ip = '174.70.34.126'
guard_port = 4567

client_ip = '137.48.184.170'
client_port = 1111

spoof_src_ip =  '31.13.93.35'
start = time.time()
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.bind((client_ip,client_port))
# The client is sending the randomly selected IP address (for spoofing) to the 2nd guard node.
# And the 2nd guard node will respond with a random port which will be used to receive the 
# spoofed packets at the 2nd guard node. 
client_socket.sendto(bytes(spoof_src_ip, encoding = 'utf-8'), (guard_ip, guard_port))
receive, _ = client_socket.recvfrom(1024)
spoof_dst_port = receive.decode("utf-8")
print(spoof_dst_port)


bootstrap_start = time.time()
spoof_src_port = requests.get('http://v74nob35lel23bs6.onion/spoof/' + str(spoof_src_ip) + '/' + str(guard_ip) + '/' + str(spoof_dst_port), proxies=proxies).text
print(spoof_src_port)

client_socket.sendto(bytes(spoof_src_port, encoding = 'utf-8'), (guard_ip, guard_port))
#client_socket.close()
try:
    timeout = requests.get('http://v74nob35lel23bs6.onion/startspoofing', proxies=proxies, timeout=2)
except Exception:
    print("Reached here!!!")

bootstrap_end = time.time()
bootstrap_time = bootstrap_end - bootstrap_start
receive = bytearray(1040)
output = bytearray()
count = 0 

obj = AES.new('1234567890123456', AES.MODE_CBC, 'This is an IV456')
receiving_sp_start = time.time()
packet_received = []
while(receive != b'EOF'):
    receive, _ = client_socket.recvfrom(1040)
    
    #print(receive.decode('utf-8'))
    try:
        temp = obj.decrypt(receive)
        packet_seq = int(temp[:16], 16)
        packet_received.append(packet_seq)
        #blocknumber = int(packet_seq/packets_per_block)
        #blocklist[blocknumber] = blocklist[blocknumber] ^ (1 << (packet_seq % packets_per_block))
        output.extend(temp[16:])
        
        count += 1
    except Exception:
        pass
    #print(count)
client_socket.close()
receiving_sp_end = time.time()
receiving_sp_time = receiving_sp_end - receiving_sp_start
print("count = " + str(count))
print("Download using spoofing = " + str(receiving_sp_time) + "s")
print("Total Received Packets : " + str(len(packet_received)))

lost_packet_seq = []
for i in range(102400):
    if i not in packet_received:
        lost_packet_seq.append(i)
print(len(lost_packet_seq))

recovery_start = time.time()
response = requests.post('http://v74nob35lel23bs6.onion/retransmit', data= str(lost_packet_seq), proxies=proxies)
downloaded_data = response.content
with open("recovery_download.file", 'wb') as s:
    s.write(downloaded_data)

recovery_time = time.time() - recovery_start

print("Recovery time :" + str(recovery_time) + "s")


'''
with open("example_using_spoofing.file", 'wb') as s:
    s.write(output)


start2 = time.time()
response = requests.post('http://3x56wfqhubxbitfe.onion/download', proxies=proxies)
downloaded_data = response.content


file_name = response.headers
#print(file_name)
end2 = time.time()
print("download 2 = " + str(end2 - start2) + "s")
with open("example_tor_download.file", 'wb') as s:
    s.write(downloaded_data)

file_time = open('time.csv', 'a')
file_time.write(str(bootstrap_time) + ',' + str(receiving_sp_time) + "," + str(bootstrap_time + receiving_sp_time) + ',' +  str(end2 - start2) + ',' + str(count) +'\n')
file_time.close()

'''
