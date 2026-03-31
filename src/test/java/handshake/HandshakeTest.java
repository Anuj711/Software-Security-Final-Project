package handshake;

import java.security.SecureRandom;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import org.junit.jupiter.api.Test;

//TEST CASE TO PROVE HANDSHAKE WORKS
public class HandshakeTest {

    @Test
    public void testSessionKeyMatch() throws Exception {

        byte[] preMaster = new byte[48];
        byte[] clientRandom = new byte[32];
        byte[] serverRandom = new byte[32];

        SecureRandom rand = new SecureRandom();
        rand.nextBytes(preMaster);
        rand.nextBytes(clientRandom);
        rand.nextBytes(serverRandom);

        SecretKey clientKey = HandshakeManager.deriveSessionKey(preMaster, clientRandom, serverRandom);
        SecretKey serverKey = HandshakeManager.deriveSessionKey(preMaster, clientRandom, serverRandom);

        assertArrayEquals(clientKey.getEncoded(), serverKey.getEncoded());
    }
}