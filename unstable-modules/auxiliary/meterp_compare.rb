##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Meterpreter capabilities compare',
      'Description' => %q{
        This module compares Meterpreter sessions and shows their different capabilities (supported commands)
      },
      'Author' => [ 'mihi' ],
      'License' => MSF_LICENSE
    ))
    register_options([
      OptString.new('SESSIONS', [true, 'Specify either ALL for all sessions or a comman separated list of sessions.', 'ALL']),
    ], self.class)
  end

  def run

    current_sessions = framework.sessions.keys.sort

    if datastore['SESSIONS'] =~/all/i
      sessions = []
      framework.sessions.each do |sid, s|
        sessions << sid if s.type == 'meterpreter'
      end
    else
      sessions = datastore['SESSIONS'].split(',')
    end

    sessioninfo = []
    cmdmap = {}
    maxnamelen = 0

    print_good 'Scanning sessions:'
    sessions.each do |s|

      next if not current_sessions.include?(s.to_i)

      session = framework.sessions.get(s.to_i)

      next if session.type != 'meterpreter'

      unless session.sys
        session.core.use('stdapi')
      end

      name = "#{s.to_s.rjust(3)} | #{session.platform}"
      maxnamelen = name.length if name.length > maxnamelen
      print_status "  #{name} | #{session.sys.config.sysinfo}"
      session.commands.each do |cmd|
        cmdmap[cmd] ||= []
        cmdmap[cmd] << s
      end

      sessioninfo << { :index => s, :name => name, :groups => '' }
    end

    cmdgroups = []
    cmdgroupmap = {}

    cmdmap.each do |k,v|
      grp = cmdgroupmap[v]
      unless grp
        grp = { :members => v, :commands => [] }
        cmdgroupmap[v] = grp
        cmdgroups << grp
      end
      grp[:commands] << k
    end

    cmdgroups.sort! do |a,b| a[:commands].length <=> b[:commands].length end

    nextgroup = 'A'

    cmdgroups.each do |grp|
        grp[:name] = nextgroup
        sessioninfo.each do |info|
            if grp[:members].include? info[:index]
                info[:groups] << nextgroup
            else
                info[:groups] << ' '
            end
        end
        nextgroup = nextgroup.next
        nextgroup = 'a' if nextgroup == 'AA'
    end

    print_good 'Supported command groups:'

    sessioninfo.each do |info|
      print_status "  #{info[:name].ljust(maxnamelen)} | #{info[:groups]}"
    end

    print_good 'Commands in each group:'
    cmdgroups.each do |grp|
      print_status "  #{grp[:name]} | #{grp[:commands].to_s}"
    end
  end
end
