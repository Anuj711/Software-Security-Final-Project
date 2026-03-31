//Server Hello

package handshake;

import java.security.SecureRandom;

public class ServerHello {
    public byte[] serverRandom;

    public ServerHello() {
        serverRandom = new byte[32];
        new SecureRandom().nextBytes(serverRandom);
    }
}