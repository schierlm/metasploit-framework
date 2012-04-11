package com.metasploit.meterpreter.jailgun;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;

public class jailgun_create_string extends JailgunCommand {
	
	protected Object execute(Meterpreter meterpreter, TLVPacket request) throws JailgunException, Exception {
		return request.getStringValue(TLVType.TLV_TYPE_STRING);
	}
}
