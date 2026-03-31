package record;

import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.crypto.SecretKey;

import crypto.AESUtil;
import crypto.MACUtil;

public class RecordLayer {

    //Authenticates data with a MAC, appends it, and then encrypts the entire package
    public static byte[] encrypt(byte[] data, SecretKey key) throws Exception {

        //Generate a MAC for the original data to ensure integrity
        byte[] mac = MACUtil.generateMAC(data, key);

        //Combine the data and the MAC into a single byte array
        byte[] combined = ByteBuffer.allocate(data.length + mac.length)
                .put(data)
                .put(mac)
                .array();

        //Encrypt the combined data and MAC using AES
        return AESUtil.encrypt(combined, key);
    }

    //Decrypts the package, splits the data from the MAC, and verifies integrity
    public static byte[] decrypt(byte[] encrypted, SecretKey key) throws Exception {

        //Decrypt the full package back into its combined data + MAC form
        byte[] decrypted = AESUtil.decrypt(encrypted, key);

        //Split the decrypted bytes: the last 32 bytes are the HmacSHA256 MAC
        byte[] data = Arrays.copyOfRange(decrypted, 0, decrypted.length - 32);
        byte[] receivedMac = Arrays.copyOfRange(decrypted, decrypted.length - 32, decrypted.length);

        //Re-calculate the MAC from the extracted data
        byte[] newMac = MACUtil.generateMAC(data, key);

        //Compare the original MAC with the new one; throw an error if they don't match
        if (!Arrays.equals(receivedMac, newMac)) {
            throw new SecurityException("MAC verification failed");
        }

        return data;
    }
}