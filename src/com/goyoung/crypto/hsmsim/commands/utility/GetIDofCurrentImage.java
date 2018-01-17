package com.goyoung.crypto.hsmsim.commands.utility;

public class GetIDofCurrentImage {

	public static String Go(String sCommand) {
		if (sCommand.contains("<1101#>")) { //return a key not wrapped by MFK
			
			return "<2101#HP Atalla A8160-VAR Version: 1.30, Date: Jun 10 2011, Time: 15:07:05#F06F#1#>";
		}
		else return "";
	}
}
