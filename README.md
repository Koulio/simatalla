## simatalla: HSM Simulator

HSM "Variant Mode" personality.
 --KeyBlock mode may be added some day

Is a POJO java service that simulates a popular Hardware Security Module. 
A class called `ServerProcess` starts a plain-text TCP Service process to emulate HSM Request/Response. 
config.properties contains runtime settings and master keys

Sample usage:
```
Start the HSM Simulator as follows:
from a command prompt:
Java -cp {path to jar file}/simatalla-0.0.1-SNAPSHOT.jar com.goyoung.crypto.hsmsim.ServerProcess

1. User telnets to IP specified in the properties file // $ telnet localhost 7000
2. User sends a command 10			   : <10#4##D#>         // request to generate double length key for 2TDEA TripleDES
3. User receives command 10 response (20): <20#F6DFEAAD648A7A17E5A9CE0796440D9D##63E0#>   
// response of double length key for 2TDEA 3DES  //key is not encrypted by any master key, 
//response contains a 4 char Key Check Value, KCV at the end

4. User Sends command 10			   : <10#1#9007B8751BB7AB4EE355AF51A716113F#D#>    
// generate double length key for 2TDEA 3DES, encrypt under variant 1 of the MFK and variant 1 or KEK, 
//Provided KEK previously encrypted under variant 0 of MFK
5. User receives command 10 response (20): <20#6CEDF649AAA492B90F909AD3A6D2D54F#64B343D9C5AB8C8692122EFDA11D62F6#07CB#>
// double length key for 2TDEA 3DES encrypted by MFK.variant.1 (leftmost
and KEK.variant.1 with char Key Check Value (rightmost), and KCV at the right end

```

