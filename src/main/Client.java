package main;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Random;

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
 *
 */
public class Client implements Runnable {
	
	//maximum timeout of client used in "run" Method
	private static int sendFrequency = 5000;
	
	int clientID;
	byte[] publicKey;
	byte[] privateKey;
	Server server;

	/**
	 * Constructor of client
	 * @param clientID
	 * @param publicKey
	 * @param privateKey
	 * @param server
	 */
	private Client(int clientID, byte[] publicKey, byte[] privateKey, Server server) {
		this.clientID = clientID;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
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
	 * Methods that signs the client order with the corresponding key
	 * @param order
	 * @param publicKey
	 * @param privateKey
	 * @return byte[] : signature
	 * @throws CoseException
	 */
	private static byte[] signMessage(String order, byte[] publicKey, byte[] privateKey) throws CoseException {
		
		SCCKey key = new SCCKey(KeyType.Asymmetric, publicKey, privateKey, "EC");
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

		SCCKey key = null;
		try {
			key = SCCKey.createKey(KeyUseCase.Signing);

			byte[] publicKey = key.getPublicKeyBytes();

			int clientID = server.registerClient(publicKey);
			if (clientID == -1) {
				throw new IllegalStateException("server does not seem to accept the client registration!");
			}

			Client c = new Client(clientID, key.getPublicKeyBytes(), key.getPrivateKeyBytes(), server);
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
	private static String generateRandomMessage() throws NumberFormatException, JsonProcessingException {
		int random = new Random().nextInt(3);
		if (random == 0) {
			return Message.createBuyStockMessage(generateRandomString(12), generateRandomNumber(3));
		} else if (random == 1){
			return Message.createSellStockMessage(generateRandomString(12), generateRandomNumber(10));
		}else
		{
			return Message.createGetOrdersMessage();
		}

	}

	/** 
	 * Sending of signed message for buying/selling stock to server.
	 * Server sends a response. Message is accepted if signature can be validated.
	 * @throws CoseException
	 * @throws JsonProcessingException
	 */
	private void sendMessage(String order) throws CoseException, JsonProcessingException {
		
		String signedMessage = SignedMessage.createSignedMessage(this.clientID, order, signMessage(order, publicKey, privateKey));

		p("sending to server: " + signedMessage);
		String result = server.acceptMessage(signedMessage);
		p("result from server: " + result);

	}

	/**
	 * Auxiliary method for generating a String of a given length.
	 * Result simulates amount of stock that should be bought.
	 * @param length
	 * @return String
	 */
	private static String generateRandomNumber(int length) {

		String AlphaNumericString = "01234567890";
		StringBuilder sb = new StringBuilder(length);

		for (int i = 0; i < length; i++) {
			int index = (int) (AlphaNumericString.length() * Math.random());
			sb.append(AlphaNumericString.charAt(index));
		}

		return sb.toString();
	}

	/**
	 * Auxiliary method for generating a String of a given length.
	 * Result simulates id of stock that should be bought.
	 * @param length
	 * @return String
	 */
	private static String generateRandomString(int length) {

		String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		StringBuilder sb = new StringBuilder(length);

		for (int i = 0; i < length; i++) {
			int index = (int) (AlphaNumericString.length() * Math.random());
			sb.append(AlphaNumericString.charAt(index));
		}

		return sb.toString();
	}

	/**
	 * Auxiliary method for showing some responses/requests in the communication between client and server
	 * @param s
	 */
	private void p(String s) {
		System.out.println(Instant.now().toString() + " client " + this.clientID + ": " + s);
	}

	@Override
	public void run() {
		while (true) {
			try {
				Thread.sleep((long)(Math.random() * sendFrequency + 1));
				sendMessage(generateRandomMessage());
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
