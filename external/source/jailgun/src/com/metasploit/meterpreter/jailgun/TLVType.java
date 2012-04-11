package com.metasploit.meterpreter.jailgun;

import com.metasploit.meterpreter.TLVPacket;

/**
 * TLV types for Jailgun.
 * 
 * @author mihi
 */
public interface TLVType extends com.metasploit.meterpreter.TLVType {

	public static final int TLV_JAILGUN_EXTENSIONS = 20000;

	public static final int TLV_TYPE_JAILGUN_THROWN = TLVPacket.TLV_META_TYPE_BOOL | (TLV_JAILGUN_EXTENSIONS + 1);
	public static final int TLV_TYPE_JAILGUN_OBJREF = TLVPacket.TLV_META_TYPE_UINT | (TLV_JAILGUN_EXTENSIONS + 2);
	public static final int TLV_TYPE_JAILGUN_CLASSNAME = TLVPacket.TLV_META_TYPE_STRING | (TLV_JAILGUN_EXTENSIONS + 3);
	public static final int TLV_TYPE_JAILGUN_METHODNAME = TLVPacket.TLV_META_TYPE_STRING | (TLV_JAILGUN_EXTENSIONS + 4);
	public static final int TLV_TYPE_JAILGUN_PARAMETERTYPES = TLVPacket.TLV_META_TYPE_STRING | (TLV_JAILGUN_EXTENSIONS + 5);
	public static final int TLV_TYPE_JAILGUN_ARGUMENTS = TLVPacket.TLV_META_TYPE_RAW | (TLV_JAILGUN_EXTENSIONS + 6);
}
