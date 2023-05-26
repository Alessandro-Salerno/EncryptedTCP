package alessandrosalerno.encryptedtcp.asymmetric;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public final class PublicKeyFactory {
    public static PublicKey fromEncodedKey(String algorithm, byte[] encodedKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec kSpec = new X509EncodedKeySpec(encodedKey);
        return KeyFactory.getInstance(algorithm).generatePublic(kSpec);
    }
}
