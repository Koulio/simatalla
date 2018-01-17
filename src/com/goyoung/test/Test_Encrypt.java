package com.goyoung.test;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;

import com.goyoung.crypto.hsmsim.ServerProcess;
import com.goyoung.crypto.hsmsim.crypto.util.Load2Part3DESKey_Variant_N;
import com.goyoung.crypto.hsmsim.crypto.util.ThreeTDEA_Decrypt;
import com.goyoung.crypto.hsmsim.crypto.util.ThreeTDEA_Encrypt;

public class Test_Encrypt {

	public static void main(String[] args) throws InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchProviderException, 
	NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidCipherTextException, 
	InvalidKeySpecException, ShortBufferException, IOException {
		
		byte[] bMFK = Load2Part3DESKey_Variant_N.Go(ServerProcess.LMK0x01, 0);
		
		
		String s_test_key ="11111111111111112222222222222222";

		
		byte[] b_test_key = new byte[32];
		b_test_key=		Hex.decode(s_test_key);
		
		byte[] s_WorkingKey = ThreeTDEA_Encrypt.Go(b_test_key, bMFK);	
		
	
		System.out.println(Hex.toHexString(s_WorkingKey).toUpperCase());
		
	}

}
