require 'rex/post/meterpreter/extensions/jailgun/tlv'
require 'rex/post/meterpreter/extensions/jailgun/jailgun_error'
require 'rex/post/meterpreter/extensions/jailgun/javaclass'
require 'rex/post/meterpreter/extensions/jailgun/javaobject'

module Rex
module Post
module Meterpreter
module Extensions
module Jailgun

class Jailgun < Extension

	def initialize(client)
		super(client, 'jailgun')

		client.register_extension_aliases(
			[
				{ 
					'name' => 'jailgun',
					'ext'  => self
				},
			])
	end

	def class_for_name(name)
		return JavaClass.new(self, name)
	end
	
	def get_objref(obj)
		if obj == nil
			return 0
		elsif obj.kind_of? JavaObject
			return obj.objref
		elsif obj.kind_of? JavaClass
			return obj.class_object.objref
		elsif obj.kind_of? String
			return jailgun_create_string(obj).objref
		elsif obj.kind_of? Integer
			return jailgun_invoke("java.lang.Integer", nil, "parseInt", "java.lang.String", [obj.to_s]).objref
		else
			return get_objref obj.to_s
		end
	end
	
	def infer_argtypes(classname, args)
		raise "infer_argtypes not implemented, give argtypes yourself!"
	end
	
	def parse_object(response)
		objref = response.get_tlv_value(TLV_TYPE_JAILGUN_OBJREF)
		if objref == 0
			obj = nil
		else
			obj = JavaObject.new(self, objref, response.get_tlv_value(TLV_TYPE_JAILGUN_CLASSNAME), response.get_tlv_value(TLV_TYPE_STRING))
		end
		if(response.get_tlv_value(TLV_TYPE_JAILGUN_THROWN))
			raise JailgunError, obj
		else
			return obj
		end
	end
	
	def jailgun_create_string(value)
		request = Packet.create_request('jailgun_create_string')
		request.add_tlv(TLV_TYPE_STRING, value)
		response = client.send_request(request)
		parse_object(response)
	end

	def jailgun_free(objref)
		request = Packet.create_request('jailgun_free')
		request.add_tlv(TLV_TYPE_JAILGUN_OBJREF, objref)
		response = client.send_request(request)
		nil
	end

	def jailgun_list(classname, methodname)
		request = Packet.create_request('jailgun_list')
		request.add_tlv(TLV_TYPE_JAILGUN_CLASSNAME, classname)
		if methodname != nil
			request.add_tlv(TLV_TYPE_JAILGUN_METHODNAME, methodname)
		end
		response = client.send_request(request)
		response.get_tlv_values(TLV_TYPE_JAILGUN_PARAMETERTYPES)
	end
	
	def jailgun_invoke(classname, object, methodname, argtypes, args)
		request = Packet.create_request('jailgun_invoke')
		request.add_tlv(TLV_TYPE_JAILGUN_CLASSNAME, classname)
		request.add_tlv(TLV_TYPE_JAILGUN_OBJREF, get_objref(object))
		if methodname != nil
			request.add_tlv(TLV_TYPE_JAILGUN_METHODNAME, methodname)
		end
		request.add_tlv(TLV_TYPE_JAILGUN_PARAMETERTYPES, argtypes)
		argrefs = ""
		args.each {|arg| argrefs << [get_objref(arg)].pack('N')}
		request.add_tlv(TLV_TYPE_JAILGUN_ARGUMENTS, argrefs)
		response = client.send_request(request)
		parse_object(response)
	end
end

end; end; end; end; end
