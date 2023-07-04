Client's IP address = '137.48.184.170'
2nd Guard nodes's IP address = '174.70.34.126' 
IP address for spoofing = '31.13.93.35'

Who knows what at the beginning:
The client knows: 
    i) the onion service's URL.
    ii) The IP address of the 2nd guard node.

The 2nd gurad node knows the client's IP address.

The onion server knows nothing about the client and the 2nd guard node.

Bootstrap:

1) The client sends the randomly selected IP address (for spoofing) to the 2nd guard node.

2) The 2nd guard node responds with a random port (dst for the spoof packets) which will be 
   used to receive the spoofed packets at the 2nd guard node. 

3) The client sends the selected spoof IP address and port number, 2nd guard node's IP address
   to the onion server ovet the tor channel.

4) The onion server responds with a port(src for the spoof packets) that will be used by it 
   to send the spoofed packets to the 2nd guard node.

5) The client forwards the port(src for the spoof packets) selected by the onion server to the 
   2nd guard node.

6) Then the 2nd guard node will wait to receive the spoofed packets from the onion server.

7) The client will send a request to the onion server over tor to start spoofing.

8) The onion server will start spoofing the packets and the 2nd guard node will forwards these 
   packets to the client.

9) The client will make a list of the lost packets and will send the list to the onion server
   to retransmit these lost packets over tor.
