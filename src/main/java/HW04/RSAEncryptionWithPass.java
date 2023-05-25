package HW04;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class RSAEncryptionWithPass {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Нужно указать параметр: пароль для PBE");
            return;
        }

        String text = "Java";
        System.out.println("Шифруемый текст: " + text);

        KeyPair pair = getKeyPair();

        SecretKey secretKey = getSecretKey(args[0]);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        byte[] encrypted = getEncryptedBytes(text, pair, cipher);

        byte[] wrappedKey = getWrappedKey(pair, secretKey);
        System.out.println("Зашифрованный секретный ключ: " + Base64.getEncoder().encodeToString(wrappedKey));

        byte[] signatureBytes = getSignatureBytes(pair, encrypted);
        System.out.println("Подпись: " + Base64.getEncoder().encodeToString(signatureBytes));
    }

    private static KeyPair getKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public static SecretKey getSecretKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        return keyFactory.generateSecret(keySpec);
    }

    private static byte[] getEncryptedBytes(String text, KeyPair pair, Cipher cipher) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
        byte[] encrypted = cipher.doFinal(text.getBytes());
        System.out.println("Зашифрованнный текст: " + Base64.getEncoder().encodeToString(encrypted));
        return encrypted;
    }

    private static byte[] getWrappedKey(KeyPair pair, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException {
        String salt = "MySuperSaltSoSaltes";
        int iterationCount = 1000;
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt.getBytes(), iterationCount);
        Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_256");
        cipher.init(Cipher.WRAP_MODE, secretKey, pbeParamSpec);
        return cipher.wrap(pair.getPrivate());
    }

    private static byte[] getSignatureBytes(KeyPair pair, byte[] encrypted) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(pair.getPrivate());
        sig.update(encrypted);
        return sig.sign();
    }
}