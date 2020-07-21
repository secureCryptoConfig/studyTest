package main;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import COSE.CoseException;

public class Server extends Thread {
	static SecretKey masterKey;
	List<PublicKey> clients = Collections.synchronizedList(new ArrayList<PublicKey>());

	public synchronized int registerClient(PublicKey key) {

		if (clients.indexOf(key) == -1) {
			clients.add(key);
		}

		return clients.indexOf(key);
	}

	public static SecretKey generateKey() {
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			SecretKey key = keyGen.generateKey();
			return key;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	private boolean checkSignature(int clientID, byte[] order, byte[] sig) throws CoseException {
		//Public key of client. Public key is used for signature validation
		PublicKey key = clients.get(clientID);
		//result of the validation. Default : false
		boolean resultValidation = false;
		
		//TODO Perform validation of the given signature with 
		//the corresponding public key of the client. Store the result in 'resultValidation'
		try {
			Signature signature = Signature.getInstance("SHA512withRSA");

			signature.initVerify(key);
			signature.update(order);

			resultValidation = signature.verify(sig);
		} catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return resultValidation;
		}

		if (resultValidation == true) {
			encryptOrder(order);
		}

		return resultValidation;

	}

	private void encryptOrder(byte[] order) {

		//TODO Perform a symmetric encryption of the given order with the already defined masterKey
		
		try {
			final byte[] nonce = new byte[32];
			SecureRandom random = SecureRandom.getInstanceStrong();
			random.nextBytes(nonce);
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);

			cipher.init(Cipher.ENCRYPT_MODE, masterKey, spec);

			byte[] byteCipher = cipher.doFinal(order);

		} catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
				| BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
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
