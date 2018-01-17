package com.goyoung.test;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import com.goyoung.crypto.hsmsim.ServerProcess;
import com.goyoung.crypto.hsmsim.crypto.util.Load2Part3DESKey_Variant_N;

/**
 * Basic symmetric encryption example with CTR using DES
 */
public class Test_Decrypt
{   
    public static void main(
        String[]    args)
        throws Exception
    {
    	Security.addProvider(new BouncyCastleProvider());
   
        
        byte[] bMFK = Load2Part3DESKey_Variant_N.Go(ServerProcess.LMK0x01, 0);
        String s_test_key ="4791B313B61DAC09370BE7D920BF774C";
        byte[] b_test_key = new byte[s_test_key.getBytes().length];
        b_test_key =     Hex.decode(s_test_key);
             
        
        SecretKeySpec   key = new SecretKeySpec(bMFK, "DesEde");
        Cipher          cipher = Cipher.getInstance("DesEde/ECB/NoPadding", "BC");

        System.out.println("input : " + Hex.toHexString(b_test_key).toUpperCase());
        
        
        cipher.init(Cipher.DECRYPT_MODE, key);//, ivSpec);
        
        byte[] cipherText = new byte[cipher.getOutputSize(b_test_key.length)];
        
        int ctLength = cipher.update(b_test_key, 0, b_test_key.length, cipherText, 0);
        System.out.println("output: " + Hex.toHexString(cipherText) + " bytes: " + ctLength);
        
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];

        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        
        ptLength += cipher.doFinal(plainText, ptLength);
        

    }
}
