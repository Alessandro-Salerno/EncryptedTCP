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

public class Main {public static void main(String[] args) {
        new Thread(() -> {
            LOOP: while (true) {
                try (ServerSocket serverSocket = new ServerSocket(8000)) {
                    Socket socket = serverSocket.accept();
                    EncryptedSocket encryptedSocket = new EncryptedSocket(socket);
                    String recv = encryptedSocket.getReader().readString();
                    System.out.println("SERVER: " + recv);
                    encryptedSocket.getWriter().writeString(recv);
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
                System.out.println("CLIENT: " + encryptedSocket.getReader().readString());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).start();
    }
}