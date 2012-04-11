package com.metasploit.meterpreter.jailgun;

import java.lang.reflect.Array;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * Mapping of Java internal types to human readable type names and back.
 * 
 * @author mihi
 */
public class JavaType {

	private static Map primitiveTypes = new HashMap();
	private static Map primitiveTypeNames = new HashMap();

	static {
		primitiveTypeNames.put("I", "int");
		primitiveTypeNames.put("B", "byte");
		primitiveTypeNames.put("C", "char");
		primitiveTypeNames.put("D", "double");
		primitiveTypeNames.put("F", "float");
		primitiveTypeNames.put("I", "int");
		primitiveTypeNames.put("J", "long");
		primitiveTypeNames.put("S", "short");
		primitiveTypeNames.put("Z", "boolean");
		for (Iterator keys = primitiveTypeNames.keySet().iterator(); keys.hasNext();) {
			String key = (String) keys.next();
			primitiveTypes.put(primitiveTypeNames.get(key), key);
		}
	}

	/**
	 * Get a type name from a {@link Class} object, for example
	 * <code>int[]</code> or <code>java.lang.String</code>.
	 * 
	 * @param type
	 *            {@link Class} object
	 * @return Type name
	 */
	public static String getTypeName(Class type) {
		String internalName = Array.newInstance(type, 0).getClass().getName();
		String suffix = "";
		while (internalName.startsWith("[")) {
			suffix += "[]";
			internalName = internalName.substring(1);
		}
		if (internalName.startsWith("L")) {
			return internalName.substring(1, internalName.length() - 1).replace('/', '.') + suffix;
		} else {
			return primitiveTypeNames.get(internalName) + suffix;
		}
	}

	/**
	 * Get a comma separated list of type names from a {@link Class[]}.
	 * 
	 * @param type
	 *            {@link Class[]}
	 * @return Type names
	 */
	public static String getTypeNames(Class[] parameterTypes) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < parameterTypes.length; i++) {
			if (i != 0)
				sb.append(',');
			sb.append(getTypeName(parameterTypes[i]));
		}
		return sb.toString();
	}

	/**
	 * Get a {@link Class} object from a type name.
	 * 
	 * @param typeName
	 *            Type name
	 * @return {@link Class} object
	 */
	public static Class fromTypeName(String typeName) throws ClassNotFoundException {
		int arrayDepth = 0;
		while (typeName.endsWith("[]")) {
			arrayDepth++;
			typeName = typeName.substring(0, typeName.length() - 2);
		}
		String internalType = (String) primitiveTypes.get(typeName);
		Class result;
		if (internalType != null) {
			result = Class.forName("[" + internalType).getComponentType();
		} else {
			result = Class.forName(typeName);
		}
		if (arrayDepth > 0) {
			result = Array.newInstance(result, new int[arrayDepth]).getClass();
		}
		return result;
	}

	/**
	 * Get a {@link Class[]} from a comma separated list of type names.
	 * 
	 * @param typeNames
	 *            Type names
	 * @return {@link Class[]}
	 */
	public static Class[] fromTypeNames(String typeNames) throws ClassNotFoundException {
		StringTokenizer st = new StringTokenizer(typeNames, ",");
		Class[] result = new Class[st.countTokens()];
		for (int i = 0; i < result.length; i++) {
			result[i] = fromTypeName(st.nextToken());
		}
		return result;
	}
}
