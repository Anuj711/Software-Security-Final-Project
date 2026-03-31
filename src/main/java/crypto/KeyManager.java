//Key Loader 

package crypto;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;

public class KeyManager {

    //Loads and retrieves a PrivateKey from a JKS keystore using the provided credentials
    public static PrivateKey getPrivateKey(String keystorePath, String password, String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keystorePath), password.toCharArray());
        return (PrivateKey) ks.getKey(alias, password.toCharArray());
    }

    //Extracts a PublicKey from an X.509 certificate file
    public static PublicKey getPublicKey(String certPath) throws Exception {
        java.security.cert.Certificate cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(new FileInputStream(certPath));
        return cert.getPublicKey();
    }
}

