//Key Loader 

package crypto;

import java.io.FileInputStream;
import java.security.*;
import java.security.cert.*;

public class KeyManager {

    public static PrivateKey getPrivateKey(String keystorePath, String password, String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keystorePath), password.toCharArray());
        return (PrivateKey) ks.getKey(alias, password.toCharArray());
    }

    public static PublicKey getPublicKey(String certPath) throws Exception {
        java.security.cert.Certificate cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(new FileInputStream(certPath));
        return cert.getPublicKey();
    }
}