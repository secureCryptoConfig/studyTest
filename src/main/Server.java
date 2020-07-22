package main;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.securecryptoconfig.SCCCiphertext;
import org.securecryptoconfig.SCCException;
import org.securecryptoconfig.SCCKey;
import org.securecryptoconfig.SCCKey.KeyUseCase;
import org.securecryptoconfig.SecureCryptoConfig;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import COSE.CoseException;

public class Server extends Thread {
	static SCCKey masterKey;
	List<SCCKey> clients = Collections.synchronizedList(new ArrayList<SCCKey>());

	public synchronized int registerClient(SCCKey key) {

		if (clients.indexOf(key) == -1) {
			clients.add(key);
		}

		return clients.indexOf(key);
	}

	private boolean checkSignature(int clientID, byte[] order, byte[] signature) throws CoseException {
		//Key of client. This key is used for signature validation
		SCCKey key = clients.get(clientID);
		
		//result of the validation. Default : false
		boolean resultValidation;
		
		//TODO Perform validation of the given signature with 
		//the corresponding key of the client. Store the result in 'resultValidation'
		SecureCryptoConfig scc = new SecureCryptoConfig();
		try {
			resultValidation = scc.validateSignature(key, signature);
			if (resultValidation == true) {
				encryptOrder(order);
			}
		} catch (InvalidKeyException | SCCException e) {
			e.printStackTrace();
			return false;
		}

		return resultValidation;

	}
	
	public static SCCKey generateKey() {
		try {
			return SCCKey.createKey(KeyUseCase.SymmetricEncryption);
		} catch (SCCException | NoSuchAlgorithmException | CoseException e) {
			e.printStackTrace();
			return null;
		}
	}
	private void encryptOrder(byte[] order) throws CoseException {
		
			
		
		//TODO Perform a symmetric encryption of the given order with the already defined masterKey
		
		SecureCryptoConfig scc = new SecureCryptoConfig();
		try {
			SCCCiphertext cipher = scc.encryptSymmetric(masterKey, order);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
	}

	public String acceptMessage(String message) {

		boolean isCorrectMessage = false;

		ObjectMapper mapper = new ObjectMapper();
		try {
			SignedMessage signedMessage = mapper.readValue(message, SignedMessage.class);
			int clientId = signedMessage.getClientId();

			byte[] signature = signedMessage.getSignature();

			isCorrectMessage = checkSignature(clientId, signedMessage.getContent().getBytes(), signature);

			Message theMessage = mapper.readValue(signedMessage.getContent(), Message.class);

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

	private void p(String s) {
		System.out.println(Instant.now().toString() + " server: " + s);
	}

	@Override
	public void run() {
		while (true) {
			p("processing orders");
			// actually do something with the orders
			try {
				Thread.sleep(10000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

}
