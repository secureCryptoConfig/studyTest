package main;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.commons.collections4.map.HashedMap;
import org.apache.commons.collections4.queue.CircularFifoQueue;
import org.securecryptoconfig.PlaintextContainer;
import org.securecryptoconfig.SCCCiphertext;
import org.securecryptoconfig.SCCException;
import org.securecryptoconfig.SCCKey;
import org.securecryptoconfig.SCCKey.KeyUseCase;
import org.securecryptoconfig.SecureCryptoConfig;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import COSE.CoseException;
import main.Message.MessageType;

public class Server extends Thread {
	HashedMap<Integer, CircularFifoQueue<SCCCiphertext>> queues = new HashedMap<Integer, CircularFifoQueue<SCCCiphertext>>();
	private static int timeoutServer = 5000;
	static SCCKey masterKey;
	List<SCCKey> clients = Collections.synchronizedList(new ArrayList<SCCKey>());

	public synchronized int registerClient(SCCKey key) {

		if (clients.indexOf(key) == -1) {
			clients.add(key);
		}

		int id = clients.indexOf(key);
		queues.put(id, new CircularFifoQueue<SCCCiphertext>(100));
		return id;
	}

	private boolean checkSignature(int clientID, byte[] order, byte[] signature, MessageType type) throws CoseException {
		// Key of client. This key is used for signature validation
		SCCKey key = clients.get(clientID);

		// result of the validation. Default : false
		boolean resultValidation;

		// TODO Perform validation of the given signature with
		// the corresponding key of the client. Store the result in 'resultValidation'
		SecureCryptoConfig scc = new SecureCryptoConfig();
		try {
			resultValidation = scc.validateSignature(key, signature);
			if (resultValidation == true && type != MessageType.GetOrders) {
				SCCCiphertext cipher = encryptOrder(order);
				queues.get(clientID).add(cipher);
			}
		} catch (InvalidKeyException | SCCException e) {
			e.printStackTrace();
			return false;
		}

		return resultValidation;

	}

	private SCCCiphertext encryptOrder(byte[] order) throws CoseException {

		// TODO Perform a symmetric encryption of the given order with the already
		// defined masterKey

		SecureCryptoConfig scc = new SecureCryptoConfig();
		try {
			SCCCiphertext cipher = scc.encryptSymmetric(masterKey, order);
			return cipher;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}

	private String decryptOrder(SCCCiphertext cipher) throws CoseException {

		SecureCryptoConfig scc = new SecureCryptoConfig();
		try {
			PlaintextContainer plaintext = scc.decryptSymmetric(masterKey, cipher);
			return plaintext.toString(StandardCharsets.UTF_8);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static SCCKey generateKey() {
		try {
			return SCCKey.createKey(KeyUseCase.SymmetricEncryption);
		} catch (SCCException | NoSuchAlgorithmException | CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	public String acceptMessage(String message) {

		boolean isCorrectMessage = false;

		ObjectMapper mapper = new ObjectMapper();
		try {
			SignedMessage signedMessage = mapper.readValue(message, SignedMessage.class);
			int clientId = signedMessage.getClientId();

			byte[] signature = signedMessage.getSignature();

			Message theMessage = mapper.readValue(signedMessage.getContent(), Message.class);
			MessageType type = theMessage.getMessageType();
			
			isCorrectMessage = checkSignature(clientId, signedMessage.getContent().getBytes(), signature, type);

			p(theMessage.getMessageType().toString());
		} catch (JsonProcessingException | CoseException e) {
			e.printStackTrace();
		}

		// SAVE Message
		try {
			return Message.createServerResponsekMessage(isCorrectMessage);
		} catch (JsonProcessingException e) {
			return new String("{\"Failure\"}");
		}
	}

	public String retrieveOrders(String message) {

		boolean isCorrectMessage = false;
		int clientId = 0;
		ObjectMapper mapper = new ObjectMapper();
		try {
			SignedMessage signedMessage = mapper.readValue(message, SignedMessage.class);
			clientId = signedMessage.getClientId();

			byte[] signature = signedMessage.getSignature();

			Message theMessage = mapper.readValue(signedMessage.getContent(), Message.class);
			MessageType type = theMessage.getMessageType();
			
			isCorrectMessage = checkSignature(clientId, signedMessage.getContent().getBytes(), signature, type);

			p((String) theMessage.getMessageType().toString());
		} catch (JsonProcessingException | CoseException e) {
			e.printStackTrace();
		}

		if (isCorrectMessage == true) {
			CircularFifoQueue<SCCCiphertext> q = queues.get(clientId);
			String answer = "";
			for (int i = 0; i < q.size(); i++) {
				SCCCiphertext cipher = q.get(i);
				String decrypted = "";
				try {
					decrypted = decryptOrder(cipher);
					answer = answer + Message.createServerSendOrdersMessage(decrypted) + "\n";
				} catch (CoseException | JsonProcessingException e) {
					e.printStackTrace();
					return new String("{\"Failure\"}");
				}
			}
			return answer;
		} else {
			return new String("{\"Failure\"}");
		}
	}

	private void p(String s) {
		System.out.println(Instant.now().toString() + " server: " + s);
	}

	@Override
	public void run() {
		while (true) {
			p("processing orders");
			try {
				Thread.sleep((long) (Math.random() * timeoutServer + 1));
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

}
