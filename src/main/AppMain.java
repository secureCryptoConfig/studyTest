package main;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import org.securecryptoconfig.SecureCryptoConfig;

import COSE.CoseException;

/**
 * Starting point for client/server simulation. 
 * Defined number of clients are created, registered by the server and then started to sent 
 * automatically created messages to the server. Also the server gets started to be able
 * to retrieve clients orders
 *
 */
public class AppMain {

	private static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager
			.getLogger(AppMain.class);

	protected static HashSet<Client> clients = new HashSet<Client>();

	//client number that is simulated for server interaction
	private static int maxClients = 1;

	public static void main(String[] args) {
		Path p = Paths.get("scc-configs");
		SecureCryptoConfig.setCustomSCCPath(p);

		//Key for later Server encryption is generated
		Server.masterKey = Server.generateKey();
		logger.info("Starting server");
		
		//Server gets started
		Server server = new Server();
		ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newCachedThreadPool();
		executor.submit(server);
		//Clients are registered by the server
		try {
			for (int i = 0; i < maxClients; i++) {
				clients.add(Client.generateNewClient(server));
			}

		} catch (IllegalStateException | NoSuchAlgorithmException | CoseException e) {
			e.printStackTrace();
		}

		//Clients are started 
		for (Client s : clients) {
			executor.submit(s);
		}

	}

	/**
	 * Auxiliary method for showing some responses/requests in the communication between client and server
	 * @param s
	 */
	private static void p(String s) {
		System.out.println(Instant.now().toString() + "AppMain: " + s);
	}

}
