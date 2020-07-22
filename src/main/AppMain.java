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

public class AppMain {

	private static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager
			.getLogger(AppMain.class);

	protected static HashSet<Client> clients = new HashSet<Client>();

	private static int maxClients = 5;

	public static void main(String[] args) {
		Path p = Paths.get("scc-configs");
		SecureCryptoConfig.setCustomSCCPath(p);

		Server.masterKey = Server.generateKey();
		logger.info("Starting server");
		Server server = new Server();
		ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newCachedThreadPool();
		executor.submit(server);
		try {
			for (int i = 0; i < maxClients; i++) {
				clients.add(Client.generateNewClient(server));
			}

		} catch (IllegalStateException | NoSuchAlgorithmException | CoseException e) {
			e.printStackTrace();
		}

		for (Client s : clients) {
			executor.submit(s);
		}

	}

	private static void p(String s) {
		System.out.println(Instant.now().toString() + "AppMain: " + s);
	}

}
