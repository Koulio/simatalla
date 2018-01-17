package com.goyoung.crypto.hsmsim.Tests;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.bouncycastle.util.encoders.Hex;
import com.goyoung.crypto.hsmsim.crypto.util.DesDEBC;
import com.goyoung.crypto.hsmsim.crypto.util.PINBlockUtil;

public class Call_PinBlock {

	public static void main(String[] args) throws Exception {

		byte pb_FORMAT01 = 0x0;
		
		// Block 1
		byte[] block1 = PINBlockUtil.calculatePINBlock("1234", 	pb_FORMAT01, "987654321012");
		String s_block1 = Hex.toHexString(block1).toUpperCase();
		System.out.println(s_block1);
		
		String s_PT_KPE = "2233223322332233";
		String s_PT_KPE_1 = s_PT_KPE + s_PT_KPE;// + s_PT_KPE;
				
	    byte[] b_KPE = Hex.decode(s_PT_KPE_1);

		
		DesDEBC desdebc = new DesDEBC(b_KPE);// encrypt the new key under VariantNN of MKF
		ByteArrayInputStream in = new ByteArrayInputStream(block1);
		ByteArrayOutputStream BAOS_Encrypt = new ByteArrayOutputStream();
		desdebc.encrypt(in, block1.length, BAOS_Encrypt);
		

		
		System.out.println(new String(Hex.encode(BAOS_Encrypt.toByteArray())).toUpperCase());

	}

}
