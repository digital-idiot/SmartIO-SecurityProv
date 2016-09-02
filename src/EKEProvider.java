/**
 * Created by abhisek on 7/22/16.
 */

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Date;

public class EKEProvider {

	private String pairing_key;
	private KeyPair keyPair;
	private SecretKey access_key;
	private byte[] init_vector;

	public EKEProvider() {
		SecureRandom random = new SecureRandom();
		StringBuffer sbuf = new StringBuffer(new BigInteger(30, random).toString(32));
		for(int i=0;i<sbuf.length();i++) {
			char ch = sbuf.charAt(i);
			if(Character.isLetter(ch) && Character.isLowerCase(ch) && random.nextFloat()<0.5) {
				sbuf.setCharAt(i, Character.toUpperCase(ch));
			}
		}
		this.pairing_key = sbuf.toString();

		MessageDigest msg_digest;
		try {
			msg_digest = MessageDigest.getInstance("SHA-512", "BC");
			this.init_vector = msg_digest.digest(pairing_key.getBytes());
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException nsae) {
			nsae.printStackTrace();
		}

	}

	public EKEProvider(String k) {
		this.pairing_key = k;
		MessageDigest msg_digest;
		try {
			msg_digest = MessageDigest.getInstance("SHA-512", "BC");
			this.init_vector = msg_digest.digest(pairing_key.getBytes());
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException nsae) {
			nsae.printStackTrace();
		}
	}

	public void generateMasterKeys() {
		this.keyPair = generateECKeys();
	}

	public void generateAccessKey(PublicKey XPubKey) {
		this.access_key = generateSharedSecret(keyPair.getPrivate(), XPubKey);
	}

	public static void main(String[] args) {
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		EKEProvider ekeProvider = new EKEProvider();
		String plainText = "Look mah, I'm a message!";
		System.out.println("Original plaintext message: " + plainText);

		// Initialize two key pairs
		KeyPair keyPairA = ekeProvider.generateECKeys();
		KeyPair keyPairB = ekeProvider.generateECKeys();
		// Create two AES secret keys to encrypt/decrypt the message
		SecretKey secretKeyA = ekeProvider.generateSharedSecret(keyPairA.getPrivate(), keyPairB.getPublic());
		SecretKey secretKeyB = ekeProvider.generateSharedSecret(keyPairB.getPrivate(), keyPairA.getPublic());

		// Encrypt the message using 'secretKeyA'
		String cipherText = ekeProvider.encryptString(secretKeyA, plainText);
		System.out.println("Encrypted cipher text: " + cipherText);

		// Decrypt the message using 'secretKeyB'
		String decryptedPlainText = ekeProvider.decryptString(secretKeyB, cipherText);
		System.out.println("Decrypted cipher text: " + decryptedPlainText);
	}

	private KeyPair generateECKeys() {
		try {
			ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
			keyPairGenerator.initialize(parameterSpec);
			return keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
			e.printStackTrace();
			return null;
		}
	}

	private SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) {
		try {
			KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(publicKey, true);
			return keyAgreement.generateSecret("AES");
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
			return null;
		}
	}

	public String encryptString(SecretKey key, String plainText) {
		try {
			IvParameterSpec ivSpec = new IvParameterSpec(init_vector);
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
			byte[] plainTextBytes = plainText.getBytes("UTF-8");
			byte[] cipherText;

			cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
			int encryptLength = cipher.update(plainTextBytes, 0, plainTextBytes.length, cipherText, 0);
			encryptLength += cipher.doFinal(cipherText, encryptLength);
			return bytesToHex(cipherText);
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException
				| UnsupportedEncodingException | ShortBufferException
				| IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			return null;
		}
	}

	public String decryptString(SecretKey key, String cipherText) {
		try {
			Key decryptionKey = new SecretKeySpec(key.getEncoded(), key.getAlgorithm());
			IvParameterSpec ivSpec = new IvParameterSpec(init_vector);
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
			byte[] cipherTextBytes = hexToBytes(cipherText);
			byte[] plainText;

			cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);
			plainText = new byte[cipher.getOutputSize(cipherTextBytes.length)];
			int decryptLength = cipher.update(cipherTextBytes, 0, cipherTextBytes.length, plainText, 0);
			decryptLength += cipher.doFinal(plainText, decryptLength);

			return new String(plainText, "UTF-8");
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException
				| IllegalBlockSizeException | BadPaddingException
				| ShortBufferException | UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}
	}

	/*public static String bytesToHex(byte[] data, int length) {
		String digits = "0123456789ABCDEF";
		StringBuffer buffer = new StringBuffer();

		for (int i = 0; i != length; i++) {
			int v = data[i] & 0xff;

			buffer.append(digits.charAt(v >> 4));
			buffer.append(digits.charAt(v & 0xf));
		}

		return buffer.toString();
	}

	public static String bytesToHex(byte[] data) {
		return bytesToHex(data, data.length);
	}*/
	public String bytesToHex(byte[] data) {
		return DatatypeConverter.printHexBinary(data);
	}

	/*public static byte[] hexToBytes(String string) {
		int length = string.length();
		byte[] data = new byte[length / 2];
		for (int i = 0; i < length; i += 2) {
			data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4) + Character
					.digit(string.charAt(i + 1), 16));
		}
		return data;
	}*/
	public byte[] hexToBytes(String s) {
		return DatatypeConverter.parseHexBinary(s);
	}

	/*
	public static void main(String args[]) {
		SecureRandom random = new SecureRandom();
		//String s = new BigInteger(30, random).toString(32);
		StringBuffer sbuf = new StringBuffer(new BigInteger(30, random).toString(32));
		for (int i = 0; i < sbuf.length(); i++) {
			char ch = sbuf.charAt(i);
			if (Character.isLetter(ch) && Character.isLowerCase(ch) && random.nextFloat() < 0.5) {
				sbuf.setCharAt(i, Character.toUpperCase(ch));
			}
		}
		System.out.println(sbuf.toString());
	}
	*/

	private Certificate genSelfSignedCert(PublicKey public_key, PrivateKey private_key) throws Exception {
		X500Principal issuer = new X500Principal("CN=SAS");
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		Date notbefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
		Date notafter = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);
		X500Principal subject = new X500Principal("SUB=Self Signed");
		X509v3CertificateBuilder cert_gen = new JcaX509v3CertificateBuilder(issuer, serial, notbefore, notafter, subject, public_key);
		X509CertificateHolder cert_holder = cert_gen.build(new JcaContentSignerBuilder("SHA5121WithRSA").setProvider("BC").build(private_key));
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert_holder);
	}
}
