package com.metasploit.meterpreter.jailgun;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class jailgun_free implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		ObjectStore.instance.free(request.getIntValue(TLVType.TLV_TYPE_JAILGUN_OBJREF));
		return ERROR_SUCCESS;
	}
}
