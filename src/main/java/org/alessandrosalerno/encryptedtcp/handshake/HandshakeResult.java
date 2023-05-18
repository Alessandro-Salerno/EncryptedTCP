package org.alessandrosalerno.encryptedtcp.handshake;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public record HandshakeResult(SecretKey secretKey,
                              IvParameterSpec iv) {
}
