package com.goyoung.crypto.hsmsim.commands.crypto;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// This class generates CVV digits
public class Generate_CVV {

static final String DES_NO_PADDING = "NoPadding";

	public String  Go(String sPAN, Date expDate, String sServiceCode) throws Exception {

		KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
		SecretKey CVK = keygenerator.generateKey();

		String CVV = calculateCVV(sPAN, CVK, expDate, sServiceCode);
		return CVV;
	}

	private static String calculateCVV(String accountNo, Key cvk, Date expDate, String serviceCode) throws Exception {

		return calculateCVD(accountNo, cvk, "1508", serviceCode);// ISO Date was yyMM 1508 August 2015
	}

	private static String calculateCVD(String sPAN, Key cvk, String expDate, String serviceCode) throws Exception {

		short sixfour = 64;
		Key udka = formDESKey(sixfour, Arrays.copyOfRange(cvk.getEncoded(), 0, 8));

		byte[] block = hex2byte(zeropadRight(sPAN + expDate + serviceCode, 32));
		byte[] ba = Arrays.copyOfRange(block, 0, 8);
		byte[] bb = Arrays.copyOfRange(block, 8, 16);

		// Encrypt ba with udka
		byte[] bc = encryptData(ba, udka);
		byte[] bd = xor(bc, bb);
		// Encrypt bd Triple DES
		byte[] be = encryptData(bd, cvk);
		return decimalizeVisa(be).substring(0, 3);
	}

	static byte[] handleCrypto(byte[] data, Key key, int direction, CipherMode cipherMode, byte[] iv) throws Exception {
		byte[] result;
		String transformation = key.getAlgorithm();
		if (key.getAlgorithm().startsWith("DESede")) {
			transformation += "/" + modetoString(cipherMode) + "/" + DES_NO_PADDING;
		}
		AlgorithmParameterSpec aps = null;
		try {
			Cipher c1 = Cipher.getInstance(transformation);
			if (cipherMode != CipherMode.ECB)
				aps = new IvParameterSpec(iv);
			c1.init(direction, key, aps);
			result = c1.doFinal(data);
			if (cipherMode != CipherMode.ECB)
				System.arraycopy(result, result.length - 8, iv, 0, iv.length);
		} catch (Exception e) {
			throw new Exception(e);
		}
		return result;
	}

	public enum CipherMode {
		ECB, // Electronic Code Book.
		CBC, // Cipher-block chaining.
		CFB8, // Cipher feedback, self-synchronizing with 8 bit shift register.
		CFB64 // Cipher feedback, self-synchronizing with 64 bit shift register.
	}

	private static String decimalizeVisa(byte[] b) {
		char[] bec = hexString(b).toUpperCase().toCharArray();
		char[] bhc = new char[bec.length];
		int k = 0;
		// Select 0-9 chars
		for (char c : bec)
			if (c < 'A')
				bhc[k++] = c;
		// Select A-F chars and map them to 0-5
		char adjust = 'A' - '0';
		for (char c : bec)
			if (c >= 'A')
				bhc[k++] = (char) (c - adjust);
		System.out.println(bhc);
		return new String(bhc);
	}

	private static String modetoString(CipherMode cipherMode) throws Exception {
		switch (cipherMode) {
		case ECB:
			return "ECB";
		case CBC:
			return "CBC";
		case CFB8:
			return "CFB8";
		case CFB64:
			return "CFB64";
		default:
			throw new Exception("Unsupported cipher mode " + cipherMode);
		}
	}

	public static byte[] encryptData(byte[] data, Key key) throws Exception {
		byte[] encryptedData = {};
		encryptedData = handleCrypto(data, key, 1, Generate_CVV.CipherMode.ECB, new byte[8]);
		return encryptedData;
	}

	protected static Key formDESKey(short keyLength, byte[] clearKeyBytes) throws Exception {
		Key key = null;
		switch (keyLength) {
		case 64: {
			key = new SecretKeySpec(clearKeyBytes, "DES");
		}
			break;
		case 128: {
			// make it 3 components to work with JCE

			short onetwenty8 = 128;
			clearKeyBytes = concat(clearKeyBytes, 0, getBytesLength(onetwenty8), clearKeyBytes, onetwenty8, onetwenty8);
		}
		case 192: {
			key = new SecretKeySpec(clearKeyBytes, "DESede");
		}
		}
		if (key == null)
			throw new Exception("Unsupported DES key length: " + keyLength + " bits");
		return key;
	}

	static int getBytesLength(short keyLength) throws Exception {
		int bytesLength = 0;
		switch (keyLength) {
		case 64:
			bytesLength = 8;
			break;
		case 128:
			bytesLength = 16;
			break;
		case 192:
			bytesLength = 24;
			break;
		default:
			throw new Exception("Unsupported key length: " + keyLength + " bits");
		}
		return bytesLength;
	}

	public static byte[] hex2byte(byte[] b, int offset, int len) {
		byte[] d = new byte[len];
		for (int i = 0; i < len * 2; i++) {
			int shift = i % 2 == 1 ? 0 : 4;
			d[i >> 1] |= Character.digit((char) b[offset + i], 16) << shift;
		}
		return d;
	}

	public static byte[] hex2byte(String s) {
		if (s.length() % 2 == 0) {
			return hex2byte(s.getBytes(), 0, s.length() >> 1);
		} else {
			// Padding left zero to make it even size #Bug raised by tommy
			return hex2byte("0" + s);
		}
	}

	public static String zeropadRight(String s, int len) {
		StringBuilder d = new StringBuilder(s);
		while (d.length() < len)
			d.append('0');
		return d.toString();
	}

	public static byte[] xor(byte[] op1, byte[] op2) {
		byte[] result;
		// Use the smallest array
		if (op2.length > op1.length) {
			result = new byte[op1.length];
		} else {
			result = new byte[op2.length];
		}
		for (int i = 0; i < result.length; i++) {
			result[i] = (byte) (op1[i] ^ op2[i]);
		}
		return result;
	}

	public static final String[] hexStrings;

	static {
		hexStrings = new String[256];
		for (int i = 0; i < 256; i++) {
			StringBuilder d = new StringBuilder(2);
			char ch = Character.forDigit((byte) i >> 4 & 0x0F, 16);
			d.append(Character.toUpperCase(ch));
			ch = Character.forDigit((byte) i & 0x0F, 16);
			d.append(Character.toUpperCase(ch));
			hexStrings[i] = d.toString();
		}

	}

	public static String hexString(byte[] b) {
		StringBuilder d = new StringBuilder(b.length * 2);
		for (byte aB : b) {
			d.append(hexStrings[(int) aB & 0xFF]);
		}
		return d.toString();
	}

	public static byte[] concat(byte[] array1, int beginIndex1, int length1, byte[] array2, int beginIndex2,
			int length2) {
		byte[] concatArray = new byte[length1 + length2];
		System.arraycopy(array1, beginIndex1, concatArray, 0, length1);
		System.arraycopy(array2, beginIndex2, concatArray, length1, length2);
		return concatArray;
	}

}