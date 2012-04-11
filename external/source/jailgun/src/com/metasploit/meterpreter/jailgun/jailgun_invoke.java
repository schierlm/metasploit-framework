package com.metasploit.meterpreter.jailgun;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.lang.reflect.InvocationTargetException;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;

public class jailgun_invoke extends JailgunCommand {

	protected Object execute(Meterpreter meterpreter, TLVPacket request) throws JailgunException, Exception {
		ObjectStore store = ObjectStore.instance;
		Class type = JavaType.fromTypeName(request.getStringValue(TLVType.TLV_TYPE_JAILGUN_CLASSNAME));
		String methodName = request.getStringValue(TLVType.TLV_TYPE_JAILGUN_METHODNAME, null);
		Class[] argumentTypes = JavaType.fromTypeNames(request.getStringValue(TLVType.TLV_TYPE_JAILGUN_PARAMETERTYPES));
		byte[] argumentReferences = request.getRawValue(TLVType.TLV_TYPE_JAILGUN_ARGUMENTS);
		Object[] arguments = new Object[argumentReferences.length / 4];
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(argumentReferences));
		for (int i = 0; i < arguments.length; i++) {
			arguments[i] = store.get(in.readInt());
		}
		try {
			if (methodName == null) {
				return type.getConstructor(argumentTypes).newInstance(arguments);
			} else {
				Object object = store.get(request.getIntValue(TLVType.TLV_TYPE_JAILGUN_OBJREF));
				return type.getMethod(methodName, argumentTypes).invoke(object, arguments);
			}
		} catch (InvocationTargetException ex) {
			throw new JailgunException(ex.getCause());
		}
	}
}
