module Rex
module Post
module Meterpreter
module Extensions
module Jailgun

class JavaClass

	def initialize(jailgun, classname)
		@jailgun = jailgun
		@name = classname
	end
	
	def invoke_static_method(methodname, argtypes, *args)
		if argtypes == nil
			argtypes = jailgun.infer_argtypes(@name, methodname, args)
		end
		@jailgun.jailgun_invoke(@name, nil, methodname, argtypes, args)
	end
	
	def new_instance(argtypes, *args)
		invoke_static_method(nil, argtypes, *args)
	end
	
	def class_object()
		@jailgun.jailgun_invoke("java.lang.Class", nil, "forName", "java.lang.String", [@name])
	end
	
	# TODO method_missing?
	
	attr_accessor :name
end

end; end; end; end; end
