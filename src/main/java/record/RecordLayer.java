package record;

import crypto.AESUtil;
import crypto.MACUtil;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class RecordLayer {

    public static byte[] encrypt(byte[] data, SecretKey key) throws Exception {

        byte[] mac = MACUtil.generateMAC(data, key);

        byte[] combined = ByteBuffer.allocate(data.length + mac.length)
                .put(data)
                .put(mac)
                .array();

        return AESUtil.encrypt(combined, key);
    }

    public static byte[] decrypt(byte[] encrypted, SecretKey key) throws Exception {

        byte[] decrypted = AESUtil.decrypt(encrypted, key);

        byte[] data = Arrays.copyOfRange(decrypted, 0, decrypted.length - 32);
        byte[] receivedMac = Arrays.copyOfRange(decrypted, decrypted.length - 32, decrypted.length);

        byte[] newMac = MACUtil.generateMAC(data, key);

        if (!Arrays.equals(receivedMac, newMac)) {
            throw new SecurityException("MAC verification failed");
        }

        return data;
    }
}