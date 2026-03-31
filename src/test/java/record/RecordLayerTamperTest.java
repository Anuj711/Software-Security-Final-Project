package record;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

//TEST CASE FOR INTEGRITY CHECK (MAC)
public class RecordLayerTamperTest {

    @Test
    public void testTamperedMessageFails() throws Exception {

        //Generate a standard 128-bit AES key for the test
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey key = kg.generateKey();

        //Define a sample message and encrypt it using the RecordLayer (which adds a MAC)
        String message = "Secure Data";
        byte[] encrypted = RecordLayer.encrypt(message.getBytes(), key);

        //Manually tamper with the encrypted data by flipping a bit at index 5
        encrypted[5] ^= 1;

        //Verify that the decryption process throws a SecurityException due to the MAC mismatch
        assertThrows(SecurityException.class, () -> {
            RecordLayer.decrypt(encrypted, key);
        });
    }
}



