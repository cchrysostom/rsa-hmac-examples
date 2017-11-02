package cchrysos.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.security.*;
import java.util.Base64;

public class Main {
    static private final String message = "The quick brown fox jumps over the lazy dog. My name is Larry.";
    static private final String shortMessage = "The quick brown fox jumps over the lazy dog. My name ";
    static private final int LOOP_COUNT = 100;
    static private final int API_KEY_SIZE_BYTES = 16;
    static private final int RSA_KEY_SIZE__BITS = 512;


    public static void hmacExample()  {

        try {
            //  If you need to specify a specific random number generator. By default, SecureRandom
            //  selects the best one depending upon platform. Mac OS and Linux will be NativePRNG.
            //
            //  SecureRandom random = SecureRandom.getInstance("NativePRNG", "SUN");
            SecureRandom random = new SecureRandom();
            byte[] apiKeyBytes = new byte[API_KEY_SIZE_BYTES];
            random.nextBytes(apiKeyBytes);

            KeyGenerator hmackg = KeyGenerator.getInstance("HmacSHA512");

            for (int i=0; i < LOOP_COUNT; i++) {
                SecretKey sk = hmackg.generateKey();

                Mac mac = Mac.getInstance("HmacSHA512");
                mac.init(sk);
                byte[] digest = mac.doFinal(message.getBytes());

                if (i == 0) {
                    String secret64 = Base64.getEncoder().encodeToString(sk.getEncoded());
                    System.out.printf("HMA API key: %d, %s\n", apiKeyBytes.length, DatatypeConverter.printHexBinary(apiKeyBytes));
                    System.out.printf("HMAC API key secret: %d, %s\n", sk.getEncoded().length, secret64);
                }
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }


    public static void rsaExample() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "SunJSSE");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(RSA_KEY_SIZE__BITS, random);

            for (int i=0; i < LOOP_COUNT; i++) {
                KeyPair pair = keyGen.generateKeyPair();
                pair.getPrivate().getEncoded();
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, pair.getPrivate());

                String rsaMsgEnc = Base64.getEncoder().encodeToString(cipher.doFinal(shortMessage.getBytes("UTF-8")));
                if (i == 0) {
                    System.out.printf("RSA API key: %d, %s\n", pair.getPublic().getEncoded().length, DatatypeConverter.printHexBinary(pair.getPublic().getEncoded()));
                    System.out.printf("RSA API secret: %d, %s\n", pair.getPrivate().getEncoded().length, Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
                    System.out.printf("RSA encrypted message: %s\n", rsaMsgEnc);
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static void main(String[] args) {
        long start = System.currentTimeMillis();
        Main.rsaExample();
        long end = System.currentTimeMillis();
        long rsaElapsed = end - start;

        System.out.println("-----------------------------------------------------------------");
        long hmacStart = System.currentTimeMillis();
        Main.hmacExample();
        long hmacEnd = System.currentTimeMillis();

        long elapsedHmac = hmacEnd - hmacStart;
        System.out.printf("Elapsed RSA time: %d milliseconds\n", rsaElapsed);
        System.out.printf("HMAC elapsed: %d milliseconds\n", elapsedHmac);
    }
}
