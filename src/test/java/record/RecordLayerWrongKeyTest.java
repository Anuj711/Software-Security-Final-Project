package record;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

//TEST CASE FOR CONFIDENTIALITY CHECK
public class RecordLayerWrongKeyTest {

    @Test
    public void testTamperedMessageFails() throws Exception {

        //Generate a 128-bit AES key for the test session
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey key = kg.generateKey();

        //Encrypt a sample message using the RecordLayer's combined MAC and AES process
        String message = "Secure Data";

        byte[] encrypted = RecordLayer.encrypt(message.getBytes(), key);

        // Manually alter a byte in the encrypted data to simulate a corruption or tampering attempt
        encrypted[5] ^= 1;

        //Ensure that the decryption fails with a SecurityException when the data integrity is compromised
        assertThrows(SecurityException.class, () -> {
            RecordLayer.decrypt(encrypted, key);
        });
    }
}


