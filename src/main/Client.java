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


public class Client implements Runnable {

	int clientID;
	SCCKey key;
	Server server;

	private Client(int clientID, SCCKey pair, Server server) {
		this.clientID = clientID;
		this.key = pair;
		this.server = server;
	}

	public int getID() {
		return this.clientID;
	}

	private SCCKey getKey() {
		return this.key;
	}

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

	private static String generateOrder() throws NumberFormatException, JsonProcessingException {
		int random = (int) (100 * Math.random());
		if (random <= 50) {
			return Message.createBuyStockMessage(generateRandomString(12), generateRandomNumber(3));
		} else {
			return Message.createSellStockMessage(generateRandomString(12), generateRandomNumber(10));
		}

	}

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
