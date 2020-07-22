package main;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

import org.securecryptoconfig.SCCException;
import org.securecryptoconfig.SCCKey;
import org.securecryptoconfig.SCCKey.KeyType;
import org.securecryptoconfig.SCCKey.KeyUseCase;
import org.securecryptoconfig.SCCSignature;
import org.securecryptoconfig.SecureCryptoConfig;

import com.fasterxml.jackson.core.JsonProcessingException;

import COSE.CoseException;

/**
 * Class that simulates the behavior of a Client that interacts with a stock-server.
 * 
 * Clients can be created automatically and register themselves at the server with their public key.
 * Orders of different types can be created automatically that will be send signed to the server.
 * The client has also the possibility to ask for already send orders
 * @author
 *
 */
public class Client implements Runnable {
	
	//maximal nu
	private static int timeoutClient = 5000;
	
	int clientID;
	SCCKey key;
	Server server;

	/**
	 * Constructor of client
	 * @param clientID
	 * @param pair : KeyPair
	 * @param server
	 */
	private Client(int clientID, SCCKey key, Server server) {
		this.clientID = clientID;
		this.key = key;
		this.server = server;
	}

	/**
	 * Getter for client ID
	 * @return int : Id of client
	 */
	public int getID() {
		return this.clientID;
	}

	/**
	 * Return key of client
	 * @return SCCKey
	 */
	public SCCKey getKey() {
		return this.key;
	}
	
	/**
	 * Methods that signs the client order with the corresponding key
	 * @param order
	 * @param key
	 * @return byte[] : signature
	 * @throws CoseException
	 */
	private static byte[] sign(String order, SCCKey key) throws CoseException {
		
		//TODO: Perform signing of the parameter order with the given SCCKey
		
		SecureCryptoConfig scc = new SecureCryptoConfig();

		SCCSignature sig;
		try {
			sig = scc.sign(key, order.getBytes());
		} catch (InvalidKeyException | SCCException | COSE.CoseException e) {
			e.printStackTrace();
			return null;
		}
		return sig.toBytes();
	}

	/**
	 * Clients are registered with their public key by the server.
	 * 
	 * The server needs the client public key for validation of signed messages.
	 * First a SCCKey for the client is generated which will then be send to the server.
	 * The server gives back a clientId and a new client will be generated.
	 * @param server
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws CoseException
	 * @throws IllegalStateException
	 */
	public static Client generateNewClient(Server server)
			throws NoSuchAlgorithmException, CoseException, IllegalStateException {

		SCCKey pair = null;
		try {
			pair = SCCKey.createKey(KeyUseCase.Signing);

			byte[] publicKey = pair.getPublicKeyBytes();

			int clientID = server.registerClient(new SCCKey(KeyType.Asymmetric, publicKey, null, pair.getAlgorithm()));
			if (clientID == -1) {
				throw new IllegalStateException("server does not seem to accept the client registration!");
			}

			Client c = new Client(clientID, pair, server);
			return c;

		} catch (SCCException | COSE.CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Automatically generates a order of a random type (buy or sell stock).
	 * Order contains an amount of stock to buy/sell from a specific stock
	 * @return
	 * @throws NumberFormatException
	 * @throws JsonProcessingException
	 */
	private static String generateOrder() throws NumberFormatException, JsonProcessingException {
		int random = (int) (100 * Math.random());
		if (random <= 50) {
			return Message.createBuyStockMessage(generateRandomString(12), generateRandomNumber(3));
		} else {
			return Message.createSellStockMessage(generateRandomString(12), generateRandomNumber(10));
		}

	}
	
	private static String generateGetOrders() throws JsonProcessingException {
			return Message.createGetOrdersMessage();
	}

	private void sendGetOrder(String order) throws CoseException, JsonProcessingException {
		SCCKey pair = this.key;

		String signedMessage = SignedMessage.createSignedMessage(this.clientID, order, sign(order, pair));

		p("sending to server: " + signedMessage);
		String result = server.retrieveOrders(signedMessage);
		p("result from server: " + result);

	}

	private void sendOrder(String order) throws CoseException, JsonProcessingException {
		SCCKey pair = this.key;

		String signedMessage = SignedMessage.createSignedMessage(this.clientID, order, sign(order, pair));

		p("sending to server: " + signedMessage);
		String result = server.acceptMessage(signedMessage);
		p("result from server: " + result);

	}

	private static String generateRandomNumber(int length) {

		String AlphaNumericString = "01234567890";
		StringBuilder sb = new StringBuilder(length);

		for (int i = 0; i < length; i++) {
			int index = (int) (AlphaNumericString.length() * Math.random());
			sb.append(AlphaNumericString.charAt(index));
		}

		return sb.toString();
	}

	private static String generateRandomString(int length) {

		String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		StringBuilder sb = new StringBuilder(length);

		for (int i = 0; i < length; i++) {
			int index = (int) (AlphaNumericString.length() * Math.random());
			sb.append(AlphaNumericString.charAt(index));
		}

		return sb.toString();
	}

	private void p(String s) {
		System.out.println(Instant.now().toString() + " client " + this.clientID + ": " + s);
	}

	@Override
	public void run() {
		while (true) {
			try {
				Thread.sleep((long)(Math.random() * timeoutClient + 1));
				sendOrder(generateOrder());
				Thread.sleep((long)(Math.random() * timeoutClient + 1));
				sendGetOrder(generateGetOrders());

			} catch (InterruptedException | CoseException e) {
				 e.printStackTrace();
			} catch (NumberFormatException e) {
				e.printStackTrace();
			} catch (JsonProcessingException e) {
				e.printStackTrace();
			}
		}

	}
}
