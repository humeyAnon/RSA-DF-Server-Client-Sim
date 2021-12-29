
// Server class - Initializes a socket and awaits for the client to request a connection
//                does Diffiehelman key exchange with RSA signature and HMAC - After all connected
//                Decrypts the message sent via Client and responds with its own encrypted message

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class Server {

    private static Encryptions secret = new Encryptions();
    private static Socket socket = null;
    private static ServerSocket server = null;
    private static BigInteger DHprivateKey, DHpublicKey, RsaN, RsaS, RsaM,
                              RsaD, publicKey = new BigInteger("65537"),
                              DHSessionKey, DHClientKey;
    private static int PORT = 1234;
    private static String clientID, clientDHKey, serverID = "FERGRTHRVERFVERFERTETYREVER32345";

    public static void main(String args[]) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
                                                  NoSuchPaddingException, BadPaddingException, InvalidKeySpecException {

        server = new ServerSocket(PORT);
        System.out.println("Waiting for the client request");

        //creating socket and waiting for client connection
        socket = server.accept();

        //read from socket to ObjectInputStream object
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

        System.out.println("Setup Phase\n-------------------------------\nMessage Received: " + ois.readObject());

        //Sending Client the public RSA key
        System.out.println("Client to Server: RSA_PK: " + publicKey.toString() + "\n");
        oos.writeObject(publicKey.toString());

        // Getting clientID
        clientID = (String) ois.readObject();
        System.out.println("HandShake Phase\n-------------------------------\nReceived ClientID: " + clientID);

        // Sending serverID
        oos.writeObject(serverID);

        // Making DH private key
        DHprivateKey = secret.DHPrivateKey();

        // Making DH public key
        DHpublicKey = secret.DHPublicKey(DHprivateKey);

        // Getting clients DH key
        clientDHKey = (String) ois.readObject();
        DHClientKey = new BigInteger(clientDHKey);

        // Signing the Servers DH key with RSA signature
        BigInteger RsaP = BigInteger.probablePrime(1024, new SecureRandom());
        BigInteger RsaQ = BigInteger.probablePrime(1024, new SecureRandom());
        RsaM = RsaP.subtract(BigInteger.ONE).multiply(RsaQ.subtract(BigInteger.ONE));
        RsaN = RsaP.multiply(RsaQ);
        RsaD = publicKey.modInverse(RsaM);
        RsaS = secret.RSASignature(DHpublicKey.toString(), RsaN, RsaD);

        System.out.println("Server to Client: Diffie-Hellman public Key, RSA signature & RSA N\n");
        oos.writeObject(DHpublicKey.toString() + "," + RsaS.toString() + "," +RsaN.toString());

        // Create diffie session key - Kba = clientDiffiePublickey ^ serverDiffiePrivate
        DHSessionKey = secret.DHSharedKey(DHClientKey, DHprivateKey);

        // Retrieved HMAC message + plain text message - Verify if they match with the session key
        String HMACmessageClient = (String) ois.readObject();
        String[] str = HMACmessageClient.split(",");

        String HMACmessage = secret.HMAC(DHSessionKey.toString(), str[1]);

        if(!HMACmessage.equals(str[0])){
            System.out.println("Session keys are invalid - Closing connection");
            closeConnection(ois,oos);
        }

        //Create HMAC from session key + plain text message - Send both to client to check session keys
        String HMACmessageServer = secret.HMAC(DHSessionKey.toString(), "If you do well you will get a fantastic mark");
        oos.writeObject(HMACmessageServer + ",If you do well you will get a fantastic mark");

        String[] clientMessage = (String[]) ois.readObject();
        System.out.println("\nData Exchange\n-------------------------------\nEncrypted message received: " + clientMessage[0] + clientMessage[1] + clientMessage[2]);

        if(!secret.HMAC(DHSessionKey.toString(), clientMessage[0].concat(clientMessage[1])).equals(clientMessage[2])) {
            System.out.println("Failed HMAC check! - Closing connection");
            closeConnection(ois,oos);
        }

        // HMAC is correct - decrypt the message from cipher, IV and session key
        System.out.println("Message decrypted: " + secret.decryptMessage(DHSessionKey.toString(),clientMessage[1],clientMessage[0]) );

        System.out.println("Encrypting & sending message: 10 didnt. Thats a pretty average riddle. How about you do better");

        oos.writeObject(secret.encryptMessage(DHSessionKey.toString(), "10 didnt. Thats a pretty average riddle. How about you do better"));

        //close resources
        closeConnection(ois, oos);

    }

    public static void closeConnection(ObjectInputStream ois, ObjectOutputStream oos) throws IOException {
        ois.close();
        oos.close();
        socket.close();
    }
}



