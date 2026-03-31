//Integrity

package crypto;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class MACUtil {

    public static byte[] generateMAC(byte[] data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(data);
    }
}