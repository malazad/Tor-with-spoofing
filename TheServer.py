import os
import shutil
import time


from stem.control import Controller
from flask import Flask
from flask import send_file, request
from scapy.all import *
from Crypto.Cipher import AES

app = Flask(__name__)

spoofed_ip = ''
src_port = 3333
dst_ip = ''
dst_port = 0
key = '1234567890123456'
@app.route('/')
def index():
  return "<h1>this is a demo .onion for research purpose only!</h1>"

@app.route('/hello')
def hello_world():
   return "<h1>Hello world!!!</h1>"

@app.route('/spoof/<ip>/<gaurd_ip>/<gaurd_port>')
def tor_download(ip, gaurd_ip, gaurd_port):
    global spoofed_ip, dst_ip, dst_port
    spoofed_ip = ip
    dst_ip = gaurd_ip
    dst_port = int(gaurd_port)
    print("spoofed ip = " + str(spoofed_ip))
    print("Dst IP = " + str(dst_ip))
    print("Dst Port = " + str(dst_port))
    return str(src_port)

@app.route('/startspoofing/')
def startSpoof():
    time.sleep(1)
    print('starting spoofing')
    print("src ip = " + spoofed_ip + " src port = " + str(src_port) + ' port type = ' + str(type(src_port)))
    print("dst ip = " + dst_ip + ' dst port = ' + str(dst_port) + ' port type = ' + str(type(dst_port)))

    fp = open("example1.file", 'rb')
    input = fp.read()
    splitLen = 1024
    obj = AES.new('1234567890123456', AES.MODE_CBC, 'This is an IV456')
    start = time.time()
    count = 0
    ss = conf.L3socket()
    #payload = input[0:20]
    #spoofed_packet = (IP(src=spoofed_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / payload)
    #payload2 = spoofed_packet['payload']
    for lines in range(0, len(input), splitLen):
        
        b = hex(count)
        #print()
        payload = obj.encrypt(bytes(b[:2] + (16-len(b)) * "0" + b[2:], encoding='utf-8') + input[lines:lines+splitLen])
        #print(payload[:16])
        elapsed1 = time.time()
        spoofed_packet = IP(src=spoofed_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / payload
        
        ss.send(spoofed_packet)
        count += 1
        end1 = time.time()
        elapsed2 = time.time()
        payload = input[lines:lines+splitLen]
        end2 = time.time()
        #time.sleep(0.0008)

        print("count = " + str(count) + ' elapsed1 time = ' + str(end1 - elapsed1) + 's 2 = ' + str(end2 - elapsed2) + 's')
    payload = b'EOF'
    spoofed_packet = IP(src=spoofed_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / payload
    ss.send(spoofed_packet)
    payload = b'EOF'
    spoofed_packet = IP(src=spoofed_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / payload
    ss.send(spoofed_packet)
    payload = b'EOF'
    spoofed_packet = IP(src=spoofed_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / payload
    ss.send(spoofed_packet)
    print("sending done!!!" + str(time.time() - start) + 's')
    return 'ok'

'''
def startSpoof():
    time.sleep(1)
    print('starting spoofing')
    payload = b"yada yada yada"
    print("src ip = " + spoofed_ip + " src port = " + str(src_port) + ' port type = ' + str(type(src_port)))
    print("dst ip = " + dst_ip + ' dst port = ' + str(dst_port) + ' port type = ' + str(type(dst_port)))
    spoofed_packet = IP(src=spoofed_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / payload
    send(spoofed_packet)
    time.sleep(0.001)
    payload = b"EOF"
    spoofed_packet = IP(src=spoofed_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / payload
    send(spoofed_packet)
    print("sending done!!!")
    return 'ok'
'''
@app.route('/download', methods=['POST', 'GET'])
def download():
    return send_file('example.file', attachment_filename='example.file')

@app.route('/retransmit', methods=['POST'])
def retransmit():
  receiveddata = request.get_data()
  receiveddata = str(receiveddata, 'utf-8')
  lost_packet_seq_list = []
  receiveddata = receiveddata[1:-1] + ','
  while receiveddata != '':
    number = receiveddata[:receiveddata.index(',')]
    receiveddata = receiveddata[receiveddata.index(',') + 1:]
    lost_packet_seq_list.append(int(number))

  print(lost_packet_seq_list)
  print(len(lost_packet_seq_list))
  fp = open("example1.file", 'rb')
  input = fp.read()
  splitLen = 1024
  obj = AES.new('1234567890123456', AES.MODE_CBC, 'This is an IV456')
  resend_data = bytes()
  for packet_seq in lost_packet_seq_list:
    resend_data = resend_data + input[packet_seq*1024 : packet_seq*1024 +splitLen]
  
  payload = obj.encrypt(resend_data)
  start = time.time()
  print('Sending recovery.......')
  return payload

print(' * Connecting to tor')

with Controller.from_port() as controller:
  controller.authenticate()

  # All hidden services have a directory on disk. Lets put ours in tor's data
  # directory.
  hidden_service_dir = os.path.join(controller.get_conf('DataDirectory', '/tmp'), 'hello_world')

  # Create a hidden service where visitors of port 80 get redirected to local
  # port 5000 (this is where Flask runs by default).

  print(" * Creating our hidden service in %s" % hidden_service_dir)
  result = controller.create_hidden_service(hidden_service_dir, 80, target_port = 5000)

  # The hostname is only available when we can read the hidden service
  # directory. This requires us to be running with the same user as tor.

  if result.hostname:
    print(" * Our service is available at %s, press ctrl+c to quit" % result.hostname)
  else:
    print(" * Unable to determine our service's hostname, probably due to being unable to read the hidden service directory")

  try:
    app.run()
  finally:
    # Shut down the hidden service and clean it off disk. Note that you *don't*
    # want to delete the hidden service directory if you'd like to have this
    # same *.onion address in the future.

    print(" * Shutting down our hidden service")
    controller.remove_hidden_service(hidden_service_dir)
    shutil.rmtree(hidden_service_dir)
