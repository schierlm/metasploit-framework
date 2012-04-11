package com.metasploit.meterpreter.jailgun;

import com.metasploit.meterpreter.CommandManager;
import com.metasploit.meterpreter.ExtensionLoader;

/**
 * Loader class to register all the jailgun commands.
 * 
 * @author mihi
 */
public class Loader implements ExtensionLoader {

	public void load(CommandManager mgr) throws Exception {
		mgr.registerCommand("jailgun_create_string", jailgun_create_string.class);
		mgr.registerCommand("jailgun_free", jailgun_free.class);
		mgr.registerCommand("jailgun_list", jailgun_list.class);
		mgr.registerCommand("jailgun_invoke", jailgun_invoke.class);
	}
}
