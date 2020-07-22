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

/**
 * Class that simulates the behavior of a stock-server that processes client
 * requests.
 * 
 * Server retrieves buy/sell orders for stock from clients. Clients can be
 * registered from the server with their public key. This public key is needed
 * to be able to check the validity of all following signed messages that the
 * client sends. The validity of signed messages will be checked and valid
 * incoming orders will be stored encrypted such that no unauthorized party can
 * see unencrypted order.
 */
public class Server extends Thread {
	// Queue to store orders of a client with a specific ID
	HashedMap<Integer, CircularFifoQueue<SCCCiphertext>> queues = new HashedMap<Integer, CircularFifoQueue<SCCCiphertext>>();
	// maximum timeout of server used in "run" Method
	private static int timeoutServer = 5000;

	// Key for encrypt orders before storing. Gets initialized with the first run of
	// AppMain.java
	static SCCKey masterKey;

	// all registered clients with their Keys
	List<SCCKey> clients = Collections.synchronizedList(new ArrayList<SCCKey>());

	/**
	 * Server retrieves key for later signature validation from client
	 * 
	 * @param key
	 * @return int : client ID
	 */
	public synchronized int registerClient(SCCKey key) {

		if (clients.indexOf(key) == -1) {
			clients.add(key);
		}

		int id = clients.indexOf(key);

		// new Queue of the client to store his later incoming orders
		queues.put(id, new CircularFifoQueue<SCCCiphertext>(100));
		return id;
	}

	/**
	 * Method to check signature validation of a incoming message.
	 * 
	 * @param clientID
	 * @param order
	 * @param signature
	 * @param type
	 * @return boolean resultValidation: shows if signature was valid
	 * @throws CoseException
	 */
	private boolean checkSignature(int clientID, byte[] order, byte[] signature, MessageType type)
			throws CoseException {
		// Key of client. This key is used for signature validation
		SCCKey key = clients.get(clientID);

		// result of the validation. Default : false
		boolean resultValidation = false;

		// TODO Perform validation of the given signature with
		// the corresponding key of the client. Store the result in 'resultValidation'
		SecureCryptoConfig scc = new SecureCryptoConfig();

		try {
			resultValidation = scc.validateSignature(key, signature);
		} catch (InvalidKeyException | SCCException e) {
			e.printStackTrace();
			return resultValidation;
		}

		return resultValidation;

	}

	/**
	 * Method for symmetric encrypting incoming order of client
	 * 
	 * @param order
	 * @return SCCCiphertext
	 * @throws CoseException
	 */
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

	/**
	 * Method for decrypting stored encrypted order if clients requests his already
	 * send orders
	 * 
	 * @param cipher
	 * @return String : all previously send orders
	 * @throws CoseException
	 */
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

	/**
	 * Generation of key for later encryption of orders
	 * 
	 * @return SCCKey
	 */
	public static SCCKey generateKey() {
		try {
			return SCCKey.createKey(KeyUseCase.SymmetricEncryption);
		} catch (SCCException | NoSuchAlgorithmException | CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Processes incoming orders. Values of messages are read out and validation
	 * process gets started. Server sends back a response to client showing if
	 * incoming order signature could be validated
	 * 
	 * @param message
	 * @return
	 */
	public String acceptMessage(String message) {

		boolean isCorrectMessage = false;
		MessageType type = null;
		int clientId = 0;
		ObjectMapper mapper = new ObjectMapper();
		try {
			SignedMessage signedMessage = mapper.readValue(message, SignedMessage.class);
			clientId = signedMessage.getClientId();

			byte[] signature = signedMessage.getSignature();

			Message theMessage = mapper.readValue(signedMessage.getContent(), Message.class);
			type = theMessage.getMessageType();

			isCorrectMessage = checkSignature(clientId, signedMessage.getContent().getBytes(), signature, type);

			p(theMessage.getMessageType().toString());

			if (isCorrectMessage == true) {
				if (type != MessageType.GetOrders) {
					SCCCiphertext cipher = encryptOrder(signedMessage.getContent().getBytes());
					queues.get(clientId).add(cipher);
					return Message.createServerResponseMessage(isCorrectMessage);
				} else {
					CircularFifoQueue<SCCCiphertext> q = queues.get(clientId);
					String answer = "";
					for (int i = 0; i < q.size(); i++) {
						SCCCiphertext cipher = q.get(i);
						String decrypted = "";
						decrypted = decryptOrder(cipher);
						answer = answer + Message.createServerSendOrdersMessage(decrypted) + "\n";
					}
					return answer;
				}
			} else {
				return Message.createServerResponseMessage(isCorrectMessage);
			}
		} catch (JsonProcessingException | CoseException e) {
			return new String("{\"Failure\"}");
		}
	}

	/**
	 * Auxiliary method for showing some responses/requests in the communication
	 * between client and server
	 * 
	 * @param s
	 */
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
