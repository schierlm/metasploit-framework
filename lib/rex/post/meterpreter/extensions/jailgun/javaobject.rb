module Rex
module Post
module Meterpreter
module Extensions
module Jailgun

class JavaObject

	def initialize(jailgun, objref, classname, string)
		@jailgun = jailgun
		@objref = objref
		@classname = classname
		@string = string
        # TODO finalizer?
    end
		
	def to_s()
		@string
	end
	
	def class()
		JavaClass.new(@jailgun, @classname)
	end

	def invoke_instance_method(methodname, argtypes, *args)
		if argtypes == nil
			argtypes = jailgun.infer_argtypes(@name, methodname, args)
		end
		@jailgun.jailgun_invoke(@classname, self, methodname, argtypes, args)
	end
	
	# TODO method_missing?

	attr_accessor :classname
	attr_accessor :objref
end

end; end; end; end; end
