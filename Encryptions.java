
// Java class that holds all the relevant functions to create keys
// and to do AES-CBC 256 encryption/decryption

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.Random;

public class Encryptions {

    private static BigInteger DHp = new BigInteger("17801190547854226652823756245015999014523215636912067427327445031444286578873702077061269525212346307956" +
            "7156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717" +
            "066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239");
    private static BigInteger DHg = new BigInteger("174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797" +
            "0949157594923683005742524387610370844734671801488761181030830437549851909834726015504946913294880833954923138" +
            "50000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730");

    private final int hashBlockSize = 32;

    public Encryptions(){}

    // Diffie private key - Xa = 1 < Xa < DHp
    public BigInteger DHPrivateKey() {

        BigInteger DHprivateKey;
        //BigInteger minLimit = new BigInteger("1");
        BigInteger maxLimit = DHp.subtract(BigInteger.ONE);
        Random ranNum = new SecureRandom();
        int length = DHp.bitLength();

        DHprivateKey = new BigInteger(length,ranNum);

        if(DHprivateKey.compareTo(BigInteger.ONE) < 0) {
            DHprivateKey = DHprivateKey.add(BigInteger.ONE);
        }

        if(DHprivateKey.compareTo(maxLimit) >= 0) {
            DHprivateKey = DHprivateKey.mod(maxLimit).add(BigInteger.ONE);
        }

       return DHprivateKey;
    }

    // Diffie public key - DHg^DiffiePrivateKey mod DHp
    public BigInteger DHPublicKey(BigInteger DHpriv) {

        BigInteger DHpub;
        DHpub = modPow(DHg,DHpriv,DHp);

        return DHpub;
    }

    // Creates the diffie shared key with the given variables
    public BigInteger DHSharedKey(BigInteger base, BigInteger exponent) {

        BigInteger DiffieShared = modPow(base, exponent, DHp);

        return DiffieShared;
    }

    // Creates the RSA signature
    public BigInteger RSASignature(String DHPublicKey, BigInteger RsaN, BigInteger RsaD) throws NoSuchAlgorithmException {
        BigInteger RsaS;

        MessageDigest d = MessageDigest.getInstance("SHA-256");
        d.update(DHPublicKey.getBytes(), 0, DHPublicKey.length());

        BigInteger hashM = new BigInteger(1, d.digest());

        RsaS = modPow(hashM, RsaD, RsaN);

    return RsaS;
    }

    // Verify RSA signature
    public boolean RSAsignatureVerify(String DHPublicKey, BigInteger signature, BigInteger n, BigInteger RsaD) throws NoSuchAlgorithmException {

        MessageDigest d = MessageDigest.getInstance("SHA-256");
        d.update(DHPublicKey.getBytes(),0,DHPublicKey.length());

        BigInteger DiffiePublicKey = new BigInteger(1, d.digest());

        if(DiffiePublicKey.equals(modPow(signature,RsaD,n))){
            return true;
        }
        return false;
    }

    // Fast modula exponent function
    public BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulo) {
        BigInteger RsaS = BigInteger.ONE;

        while(exponent.compareTo(BigInteger.ZERO) > 0) {
            if(exponent.testBit(0)) {
                RsaS = (RsaS.multiply(base)).mod(modulo);
            }
            exponent = exponent.shiftRight(1);
            base = (base.multiply(base)).mod(modulo);
        }
        return RsaS.mod(modulo);
    }

    // HMAC method with the session key and the message it needs to authenticate
    public String HMAC(String key, String message) throws NoSuchAlgorithmException, IOException {

        // Hashing session key
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        byte[] keyHash = SHA256Hash(key);
        byte[] messageBytes = message.getBytes();

        // Creating Ipad/Opad
        byte[] opad = new byte[hashBlockSize];
        byte[] ipad = new byte[hashBlockSize];

        for(int i = 0; i < keyHash.length; i++) {

            opad[i] = (byte)(keyHash[i] ^ 0x5c);
            ipad[i] = (byte)(keyHash[i] ^ 0x36);

        }

        // Hash opad and ipad byte arrays
        byte[] keyOpadHash = d.digest(opad);
        byte[] keyIpadHash = d.digest(ipad);

        // Concat all byte arrays then hash the final array
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(keyOpadHash);
        os.write(keyIpadHash);
        os.write(messageBytes);

        byte[] HMACfinal = d.digest(os.toByteArray());

        //Convert byte array to hex string
        StringBuilder sb = new StringBuilder();
        for(byte b : HMACfinal){
            sb.append(String.format("%02x",b));
        }

        return sb.toString();
    }

    // Encrypts the plain text message - Splits up into 16byte blocks and does AES-CBC for a final cipher text message
    // This function is a little bit overkill and probably could have been re-written like the decryptMessage but.. Exams and stuff & it works.
    public String[] encryptMessage(String key, String message) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException,
                                                                      NoSuchPaddingException, IOException {

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        byte[] finalCipher;
        String[] returnArray = new String[3];

        // Making the arrays to store the byte data in - C2 is storing the cipherText byte data
        byte[][] cipher1 = new byte[5][];
        byte[][] c2 = new byte[4][];

        // Making 16byte IV
        SecureRandom sc = new SecureRandom();
        cipher1[0] = new byte[16];

        // Storing the IV for HMAC & in the returnArray
        sc.nextBytes(cipher1[0]);
        byte[] IV = cipher1[0];
        String IVString = byteToHex(IV);

        returnArray[0] = byteToHex(cipher1[0]);

        // Getting byte data from the H(key) - Message data
        byte[] hashKey = SHA256Hash(key);
        byte[] messageB = message.getBytes();

        // Splitting message into 4 16byte arrays
        byte[] p1 = Arrays.copyOfRange(messageB,0,16);
        byte[] p2 = Arrays.copyOfRange(messageB,16,32);
        byte[] p3 = Arrays.copyOfRange(messageB,32,48);
        byte[] p4 = Arrays.copyOfRange(messageB,48,64);

        // Storing the sub arrays in cipher1 main array
        // First index will store the IV XOR p1 to start off the CBC
        cipher1[0] = xorArray(cipher1[0], p1);
        cipher1[1] = p2;
        cipher1[2] = p3;
        cipher1[3] = p4;

        //C2 storing the cipher text blocks
        c2[0] = AESCipher(hashKey,cipher1[0]);
        os.write(c2[0]);

        // Completing the rest of the CBC blocks
        for(int i = 1 ; i < 4; i++) {
            c2[i] = AESCipher(hashKey, xorArray(c2[i-1],cipher1[i]));
            os.write(c2[i]);
        }

        finalCipher = os.toByteArray();

        // Storing the cipher message
        returnArray[1] = byteToHex(finalCipher); //sb.toString();

        // Storing the HMAC - IV + Encrypted Message output
        returnArray[2] = HMAC(key, IVString.concat(byteToHex(finalCipher)));

        // Return IV + EncryptedMessage + M
        return returnArray;
    }

    // Decrypts the encrypted message with AES-256 and returns the plain text
    public String decryptMessage(String key, String message, String IV) throws NoSuchAlgorithmException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
                                                                               InvalidKeyException, IOException {

        ByteArrayOutputStream os = new ByteArrayOutputStream();

        byte[] IVbytes = HexStringToByteArray(IV);
        byte[] hashKey = SHA256Hash(key);
        byte[] messageBytes = HexStringToByteArray(message);

        // Holds the 16byte blocks of the cipher message
        byte[][] totalCipher = new byte[4][];
        // C1 holds the cipher text after AES
        byte[][] c1 = new byte[4][];
        // C2 holds the plain text after XOR
        byte[][] c2 = new byte[4][];

        totalCipher[0] = Arrays.copyOfRange(messageBytes,0,16);
        totalCipher[1] = Arrays.copyOfRange(messageBytes,16,32);
        totalCipher[2] = Arrays.copyOfRange(messageBytes,32,48);
        totalCipher[3] = Arrays.copyOfRange(messageBytes,48,64);

        // Decryption for AES-CBC
        for(int i = 0; i < 4; i++) {
            c1[i] = AESDecrypt(hashKey, totalCipher[i]);
            if(i == 0){
                c2[i] = xorArray(IVbytes, c1[i]);
            }
            else{
                c2[i] = xorArray(totalCipher[i-1],c1[i]);
            }
            os.write(c2[i]);
        }
        return os.toString();
    }

    // AES-256 cipher function
    public byte[] AESCipher(byte[] keyHash, byte[] plainText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException,
                                                                     IllegalBlockSizeException {

        SecretKey AESkey = new SecretKeySpec(keyHash, 0, keyHash.length, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, AESkey);

        return cipher.doFinal(plainText);
    }

    // AES-256 decryption function
    public byte[] AESDecrypt(byte[] keyHash, byte[] cipherText) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException,
                                                                       IllegalBlockSizeException {

        SecretKey AESkey = new SecretKeySpec(keyHash, 0, keyHash.length, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, AESkey);

        return cipher.doFinal(cipherText);

    }

    // Helper function to returned a XOR array from 2 byte array inputs
    public byte[] xorArray(byte[] A1, byte[] A2){
        for(int i = 0; i < A1.length; i++){
            A1[i] = (byte)(A1[i] ^ A2[i]);
        }
        return A1;
    }

    // Helper function to make hex string from byte data
    public String byteToHex(byte[] input) {
        StringBuilder sb = new StringBuilder();
        for(byte b : input){
            sb.append(String.format("%02x",b));
        }
        return sb.toString();
    }

    // Helper function to convert a hex string to byte array - As 2 hex digits for 1 byte
    public static byte[] HexStringToByteArray(String s) {
        byte[] data = new byte[s.length()/2];
        for(int i=0;i < s.length();i+=2) {
            data[i/2] = (Integer.decode("0x"+s.charAt(i)+s.charAt(i+1))).byteValue();
        }
        return data;
    }

    // Helper function to hash strings and return the byte array
    public byte[] SHA256Hash(String key) throws NoSuchAlgorithmException {

        MessageDigest d = MessageDigest.getInstance("SHA-256");
        byte[] keyHash = d.digest(key.getBytes());

        return keyHash;
    }

}
