package org.alessandrosalerno.encryptedtcp;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Main {
    public static boolean compareKeys(byte[] k1, byte[] k2) {
        if (k1.length != k2.length)
            return false;

        for (int i = 0; i < k1.length; i++) {
            if (k1[i] != k2[i])
                return false;
        }

        return true;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        new Thread(() -> {
            LOOP: while (true) {
                try (ServerSocket serverSocket = new ServerSocket(8000)) {
                    Socket socket = serverSocket.accept();
                    EncryptedSocket encryptedSocket = new EncryptedSocket(socket);
                    encryptedSocket.getWriter().writeString(encryptedSocket.getReader().readString());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }).start();

        new Thread(() -> {
            try {
                Socket socket = new Socket("localhost", 8000);
                EncryptedSocket encryptedSocket = new EncryptedSocket(socket);
                encryptedSocket.getWriter().writeString("Hello world");
                System.out.println(encryptedSocket.getReader().readString());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).start();
    }
}