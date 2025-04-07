import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.security.*;


/**
 * Client class that initiates a connection, performs key exchange, encrypts data, and sends it.
 */
class Client {
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 5050);
        System.out.println("Connected to server.");

        // Setup input and output streams
        ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

        // Receive Server's public key
        PublicKey serverPublicKey = (PublicKey) input.readObject();

        // Generate Client's DH key pair
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(((DHPublicKey) serverPublicKey).getParams());
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // Send Client's public key to Server
        output.writeObject(keyPair.getPublic());
        output.flush();

        // Generate shared secret key
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(serverPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        SecretKey secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

        System.out.println("Shared secret key established.");

        // Create SecureData object
        SecureData data = new SecureData("Alice", "Confidential Message", 123.45);
        System.out.println("Original Data: " + data);

        // Serialize and Encrypt Data
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(data);
        byte[] serializedData = bos.toByteArray();
        byte[] encryptedData = CryptoUtils.encrypt(serializedData, secretKey);

        // Send Encrypted Data
        output.writeObject(encryptedData);
        output.flush();

        socket.close();
    }
}