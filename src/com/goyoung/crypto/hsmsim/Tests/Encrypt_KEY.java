package com.goyoung.crypto.hsmsim.Tests;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

import com.goyoung.crypto.hsmsim.crypto.util.DesDEBC;
import com.goyoung.crypto.hsmsim.crypto.util.Load2Part3DESKey_Variant_N;

public class Encrypt_KEY {

	public static void main(String[] args) throws InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidCipherTextException, InvalidKeySpecException, ShortBufferException, IOException {
		// TODO Auto-generated method stub
		String s_PT_KPE = "2233223322332233";
		String s_PT_MFK = "2ABC3DEF4567018998107645FED3CBA2";
		//String s_PT_eKEK= "47F102C2D4DE29C41DE1CF689E9699D63D1DFD44D1AD3157";
		
	    byte[] b_KPE = Hex.decode(s_PT_KPE);
		//byte[] b_eKek = Hex.decode(s_PT_eKEK);
		byte[] bMFK = Load2Part3DESKey_Variant_N.Go(s_PT_MFK, 1);
		
		DesDEBC desdebc = new DesDEBC(bMFK);// encrypt the new key under VariantNN of MKF
		ByteArrayInputStream in = new ByteArrayInputStream(b_KPE);
		ByteArrayOutputStream BAOS_Encrypt = new ByteArrayOutputStream();
		desdebc.encrypt(in, b_KPE.length, BAOS_Encrypt);
		
//		DesDEBC desdebc_2_Dec = new DesDEBC(bMFK);// encrypt the new key under VariantNN of MKF
//		ByteArrayInputStream in0 = new ByteArrayInputStream(b_eKek);
//		ByteArrayOutputStream BAOS_Decrypt = new ByteArrayOutputStream();
//		desdebc_2_Dec.decrypt(in0, b_kek.length, BAOS_Decrypt);
//		
		//byte[] e_KPE = Arrays.copyOfRange(out.toByteArray(), 0, 16);
		System.out.println("Encrypted: " + new String(Hex.encode(BAOS_Encrypt.toByteArray())).toUpperCase());
		//System.out.println("Decrypted: " + new String(Hex.encode(BAOS_Decrypt.toByteArray())).toUpperCase());
		
	}

}
