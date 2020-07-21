package main;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.time.Instant;

import com.fasterxml.jackson.core.JsonProcessingException;

import COSE.CoseException;

public class Client implements Runnable {

	int clientID;
	KeyPair key;
	Server server;

	private Client(int clientID, KeyPair pair, Server server) {
		this.clientID = clientID;
		this.key = pair;
		this.server = server;
	}

	public int getID() {
		return this.clientID;
	}

	private KeyPair getKey() {
		return this.key;
	}
	
	private static byte[] sign(String order, KeyPair pair) {

		//TODO: Perform signing of the parameter order with the given KeyPair
		
		Signature signature;
		try {
			signature = Signature.getInstance("SHA512withRSA");
			signature.initSign(pair.getPrivate());
			signature.update(order.getBytes());
			return signature.sign();
		} catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static Client generateNewClient(Server server) {

		KeyPair pair = null;

		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");

			keyPairGenerator.initialize(4096);
			pair = keyPairGenerator.generateKeyPair();

		} catch (NoSuchAlgorithmException e) {

			e.printStackTrace();
		}
		PublicKey publicKey = pair.getPublic();
		int clientID = server.registerClient(publicKey);
		if (clientID == -1) {
			throw new IllegalStateException("server does not seem to accept the client registration!");
		}

		Client c = new Client(clientID, pair, server);
		return c;
	}

	private static String generateOrder() throws NumberFormatException, JsonProcessingException {
		int random = (int) (100 * Math.random());
		if (random <= 50) {
			return Message.createBuyStockMessage(generateRandomString(12), generateRandomNumber(3));
		} else {
			return Message.createSellStockMessage(generateRandomString(12), generateRandomNumber(10));
		}

	}


	private void sendOrder(String order) throws CoseException, JsonProcessingException {
		KeyPair pair = this.key;

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
				Thread.sleep(500 + (long) (1000 * Math.random()));
				sendOrder(generateOrder());
				Thread.sleep(5000 + (long) (5000 * Math.random()));

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
