package com.metasploit.meterpreter.jailgun;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class jailgun_list implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		Class type = JavaType.fromTypeName(request.getStringValue(TLVType.TLV_TYPE_JAILGUN_CLASSNAME));
		String methodName = request.getStringValue(TLVType.TLV_TYPE_JAILGUN_METHODNAME, null);
		if (methodName == null) {
			Constructor[] constructors = type.getConstructors();
			for (int i = 0; i < constructors.length; i++) {
				response.addOverflow(TLVType.TLV_TYPE_JAILGUN_PARAMETERTYPES, JavaType.getTypeNames(constructors[i].getParameterTypes()));
			}
		} else {
			Method[] methods = type.getMethods();
			for (int i = 0; i < methods.length; i++) {
				if (methods[i].getName().equals(methodName)) {
					response.addOverflow(TLVType.TLV_TYPE_JAILGUN_PARAMETERTYPES, JavaType.getTypeNames(methods[i].getParameterTypes()));
				}
			}
		}
		return ERROR_SUCCESS;
	}
}
