package com.metasploit.meterpreter.jailgun;

import java.util.ArrayList;
import java.util.List;

/**
 * Object store that holds all the objects referenced by object IDs.
 * 
 * @author mihi
 */
public class ObjectStore {

	/**
	 * The only instance of this object used by Jailgun.
	 */
	public static ObjectStore instance = new ObjectStore();

	private List liveObjects = new ArrayList();
	private int firstIndex = 1;

	/**
	 * Get an object from the object store.
	 * 
	 * @param objref
	 *            Object Reference
	 * @return Object
	 */
	public synchronized Object get(int objref) {
		if (objref < firstIndex || objref >= firstIndex + liveObjects.size())
			return null;
		return liveObjects.get(objref - firstIndex);
	}

	/**
	 * Add an object to the object store.
	 * 
	 * @param object
	 *            Object to add
	 * @return New object ID
	 */
	public synchronized int add(Object object) {
		liveObjects.add(object);
		return firstIndex + liveObjects.size() - 1;
	}

	/**
	 * Free the object stored in the object store. Later accesses will return
	 * <code>null</code>.
	 * 
	 * @param objid
	 *            Object to free
	 */
	public synchronized void free(int objid) {
		liveObjects.set(objid - firstIndex, null);
		while (liveObjects.size() > 0 && liveObjects.get(0) == null) {
			liveObjects.remove(0);
			firstIndex++;
		}
	}
}
