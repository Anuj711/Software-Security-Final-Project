// Client class

package handshake;

import java.security.SecureRandom;

public class ClientHello {
    public byte[] clientRandom;

    public ClientHello() {
        clientRandom = new byte[32];
        new SecureRandom().nextBytes(clientRandom);
    }
}

