package com.goyoung.crypto.hsmsim.crypto.util;

import java.util.regex.Pattern;

public class PINBlockUtil {

	private static final Pattern SPLIT_PIN_PATTERN = Pattern.compile("[ :;,/.]");

	/**
	 * PIN Block Format adopted by ANSI (ANSI X9.8) and is one of two formats
	 * supported by the ISO (ISO 95641 - format 0).
	 */
	public static final byte FORMAT01 = (byte) 01;

	/**
	 * PIN Block Format 02 supports Douctel ATMs.
	 */
	public static final byte FORMAT02 = (byte) 02;

	/**
	 * PIN Block Format 03 is the Diabold Pin Block format.
	 */
	public static final byte FORMAT03 = (byte) 03;

	/**
	 * PIN Block Format 04 is the PIN block format adopted by the PLUS network.
	 */
	public static final byte FORMAT04 = (byte) 04;

	/**
	 * PIN Block Format 05 is the ISO 9564-1 Format 1 PIN Block.
	 */
	public static final byte FORMAT05 = (byte) 05;

	/**
	 * PIN Block Format 34 is the standard EMV PIN block format. Is only
	 * avaliable as output of EMV PIN change commands.
	 */
	public static final byte FORMAT34 = (byte) 34;

	/**
	 * PIN Block Format 35 is the required by Europay/MasterCard for their Pay
	 * Now & Pay Later products.
	 */
	public static final byte FORMAT35 = (byte) 35;

	/**
	 * PIN Block Format 41 is the Visa format for PIN change without using the
	 * current PIN.
	 */
	public static final byte FORMAT41 = (byte) 41;

	/**
	 * PIN Block Format 42 is the Visa format for PIN change using the current
	 * (old) PIN.
	 */
	public static final byte FORMAT42 = (byte) 42;

	/**
	 * Proprietary PIN Block format.
	 * <p>
	 * Most Security Modules use a proprietary PIN Block format when encrypting
	 * the PIN under the LMK of the Security Module hence this format
	 * (FORMAT00).
	 *
	 * <p>
	 * This is not a standard format, every Security Module would interpret
	 * FORMAT00 differently.
	 *
	 * So, no interchange would accept PIN Blocks from other interchanges using
	 * this format. It is useful only when working with PIN's inside your own
	 * interchange.
	 * </p>
	 */
	public static final byte FORMAT00 = (byte) 00;

	/**
	 * The minimum length of the PIN
	 */
	private static final short MIN_PIN_LENGTH = 4;
	/**
	 * The maximum length of the PIN
	 */
	private static final short MAX_PIN_LENGTH = 12;

	/**
	 * a 64-bit block of ones used when calculating pin blocks
	 */
	private static final byte[] fPaddingBlock = CryptoUtils.hex2byte("FFFFFFFFFFFFFFFF");

	private static boolean isVSDCPinBlockFormat(byte pinBlockFormat) {
		return pinBlockFormat == FORMAT41 || pinBlockFormat == FORMAT42;
	}

	public static byte[] calculatePINBlock(String pin, byte pinBlockFormat,
			String accountNumber) throws Exception {
		byte[] pinBlock = null;
		String oldPin = null;
		if (pinBlockFormat == FORMAT42) {
			String[] p = splitPins(pin);
			pin = p[0];
			oldPin = p[1];
			if (oldPin.length() < MIN_PIN_LENGTH
					|| oldPin.length() > MAX_PIN_LENGTH)
				throw new Exception("Invalid OLD PIN length: "
						+ oldPin.length());
			if (!CryptoUtils.isNumeric(oldPin, 10))
				throw new Exception("Invalid OLD PIN decimal digits: " + oldPin);
		}
		if (pin.length() < MIN_PIN_LENGTH || pin.length() > MAX_PIN_LENGTH)
			throw new Exception("Invalid PIN length: " + pin.length());
		if (!CryptoUtils.isNumeric(pin, 10))
			throw new Exception("Invalid PIN decimal digits: " + pin);
		if (isVSDCPinBlockFormat(pinBlockFormat)) {
			if (accountNumber.length() != 16)
				throw new Exception(
						"Invalid UDK-A: "
								+ accountNumber
								+ ". The length of the UDK-A must be 16 hexadecimal digits");
		} else if (accountNumber.length() != 12)
			throw new Exception(
					"Invalid Account Number: "
							+ accountNumber
							+ ". The length of the account number must be 12 (the 12 right-most digits of the account number excluding the check digit)");
		switch (pinBlockFormat) {
		case FORMAT00: // same as FORMAT01
		case FORMAT01: {
			// Block 1
			byte[] block1 = CryptoUtils.hex2byte(new String(
					formatPINBlock(pin, 0x0)));

			// Block 2
			byte[] block2 = CryptoUtils.hex2byte("0000" + accountNumber);
			// pinBlock
			pinBlock = CryptoUtils.xor(block1, block2);
		}
			break;
		case FORMAT03: {
			char[] block = CryptoUtils.hexString(fPaddingBlock).toCharArray();
			System.arraycopy(pin.toCharArray(), 0, block, 0, pin.length());
			pinBlock = CryptoUtils.hex2byte(new String(block));
		}
			break;
		case FORMAT34: {
			pinBlock = CryptoUtils.hex2byte(new String(formatPINBlock(pin, 0x2)));
		}
			break;
		case FORMAT35: {
			// Block 1
			byte[] block1 = CryptoUtils.hex2byte(new String(
					formatPINBlock(pin, 0x2)));

			// Block 2
			byte[] block2 = CryptoUtils.hex2byte("0000" + accountNumber);
			// pinBlock
			pinBlock = CryptoUtils.xor(block1, block2);
		}
			break;
		case FORMAT41: {
			// Block 1
			byte[] block1 = CryptoUtils.hex2byte(new String(
					formatPINBlock(pin, 0x0)));

			// Block 2 - account number should contain Unique DEA Key A (UDK-A)
			byte[] block2 = CryptoUtils.hex2byte("00000000"
					+ accountNumber.substring(accountNumber.length() - 8));
			// pinBlock
			pinBlock = CryptoUtils.xor(block1, block2);
		}
			break;
		case FORMAT42: {
			// Block 1
			byte[] block1 = CryptoUtils.hex2byte(new String(
					formatPINBlock(pin, 0x0)));

			// Block 2 - account number should contain Unique DEA Key A (UDK-A)
			byte[] block2 = CryptoUtils.hex2byte("00000000" + accountNumber.substring(accountNumber.length() - 8));
			// Block 3 - old pin
			byte[] block3 = CryptoUtils.hex2byte(CryptoUtils.zeropadRight(oldPin, 16));
			// pinBlock
			pinBlock = CryptoUtils.xor(block1, block2);
			pinBlock = CryptoUtils.xor(pinBlock, block3);
		}
			break;
		default:
			throw new Exception("Unsupported PIN format: " + pinBlockFormat);
		}
		return pinBlock;
	}

	private static String[] splitPins(String pins) {
		String[] pin = new String[2];
		String[] p = SPLIT_PIN_PATTERN.split(pins);
		pin[0] = p[0];
		if (p.length >= 2)
			pin[1] = p[1];
		return pin;
	}

	private static char[] formatPINBlock(String pin, int checkDigit) {
		char[] block = CryptoUtils.hexString(fPaddingBlock).toCharArray();
		char[] pinLenHex = String.format("%02X", pin.length()).toCharArray();
		pinLenHex[0] = (char) ('0' + checkDigit);

		// pin length then pad with 'F'
		System.arraycopy(pinLenHex, 0, block, 0, pinLenHex.length);
		System.arraycopy(pin.toCharArray(), 0, block, pinLenHex.length,pin.length());
		return block;
	}

}
