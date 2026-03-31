//Integrity

package crypto;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class MACUtil {

    //Generates a Message Authentication Code (MAC) using HmacSHA256 to verify data integrity
    public static byte[] generateMAC(byte[] data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(data);
    }
}

