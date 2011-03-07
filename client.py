from scapy.all import *

data = "\x01\xcc\xcc\xcc\xcc"
encrypted_data = ""
key_info = 0x4142
key = [0, 0]

key[0] = key_info & 0xFF
key[1] = (key_info >> 8) & 0xFF

for c in data:
	encrypted_data += chr((ord(c) ^ key[0]) ^ key[1])

print encrypted_data
print "0x%02x" % key[0]
print "0x%02x" % key[1]
pkt = IP(src='10.4.31.151', dst='10.4.31.131')/ICMP(type=8, code=0, chksum=key_info)/encrypted_data
send(pkt)
