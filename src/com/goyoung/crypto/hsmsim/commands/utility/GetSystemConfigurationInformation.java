package com.goyoung.crypto.hsmsim.commands.utility;

public class GetSystemConfigurationInformation {

	public static String Go(String sCommand) {
		// TODO Auto-generated method stub
		if (sCommand.contains("<1110#>")) { //return a key not wrapped by MFK
			
			//TODO: make this configurable
			return "<2110#Axx160, Version: 1.30, Date: Jun 10 2011, Time:"+
"15:13:05#HP Atalla A8160-VAR Version: 1.30, Date: Jun 10"+
"2011, Time: 15:07:05#F06F#1#>";
		}
		return"";
	}

}
