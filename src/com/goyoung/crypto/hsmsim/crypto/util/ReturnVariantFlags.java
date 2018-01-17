package com.goyoung.crypto.hsmsim.crypto.util;

// To find the variant, Multiply the variant number by 0x08 (0x08 * variant 5 = 0x28), then XOR that to the first byte (and 17th byte if 3DES) of the clear key before encrypting or decrypting.
// To get an HSM that knows nothing of variants to accomplish the same thing, apply the variant to the clear key before importing into the HSM.
// For example, if you're encrypting a TMK under a ZMK, XOR 28000000000000002800000000000000 to the clear ZMK, then import it.

// A TMK, ZMK or KEK, all use variant 0 (equivalent to no variant at all since 0x08 * 0 = 0) 
// The vast majority of ATMs do not use variants. The most common use of variants 
// is for storing keys in a database encrypted under the appropriate variant of the MFK. 
// The Thales LMK key scheme 'U' serves the same purpose.

public class ReturnVariantFlags {

	public static String Go(int Variant) {

		if(Variant==1){
			return "0800000000000000";
		}
		else{
		
		String s_zeros = "0000000000000000";//string of 16 0's
		int i8 = 0x08;//Starting point variant 1 = 8 Hex

		//derive variant 0x8 X VariantNN = VariantFlag
		String s_iVariant = Integer.toHexString(i8 * Variant);

		String s_substring_zeros = s_zeros.substring(0,s_zeros.length() - s_iVariant.length());


		
		return s_iVariant + s_substring_zeros;
		}
	}

}

/* 

Variant | Working Key | Abbrev
-----------------------------
0 Key Exchange Key KEK, KEK-IN
1 PIN Encryption Key KPE
2 Data or Communication Key KC
3 Message Authentication Code key KMAC
3 VISA Card Verification ValuevMastercard Card Validation Code KCVV KCVC
4 PIN Verification Key KPV
5 ATM A key AATM
5 ATM B key BATM
5 ATM master key KMATM
5 Object Key KOP
6 Initialization Vector IV
6 Decimalization/Conversion Table DECTAB
7 Challenge Response Authentication Key KMACR
8 Derivation Key DK
9 Visa VSVC Master Key / EMV Master Key VSVCMK / MK
10 PIN Encryption Key - Encrypt Only KPE-EO
11 Custom MK-DL
12 Custom PMK
13 Master Message Authentication Key KMAC-MK
14 Custom none
15 none none
16 Data Encrypt Only ENC
17 Data Decrypt Only DEC
18 Generate Message Authentication Code only GMAC
19 Verify Message Authentication Code only VMAC
20 PIN Encryption Key - Decrypt Only KPE - DO
21 Custom none
22 Custom none
23 Custom none
24 Custom none
25 Custom none
26 Custom none
27 Custom none
28 Custom none
29 Custom none
30 Challenge Data none
31 Key Exchange Key - Outgoing KEK-OUT

*/
