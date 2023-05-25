package HW03;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;

public class RSAEncryption {
    public static void main(String[] args) throws Exception {
        String text = "Java";
        System.out.println("Шифруемый текст: " + text);

        // Генерируем ключи RSA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        // Зашифровываем текст алгоритмом RSA
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
        byte[] encrypted = cipher.doFinal(text.getBytes());
        System.out.println("Зашифрованнный текст: " + Base64.getEncoder().encodeToString(encrypted));

        // Генерируем подпись для зашифрованного текста
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(pair.getPrivate());
        sig.update(encrypted);
        byte[] signatureBytes = sig.sign();
        System.out.println("Подпись: " + Base64.getEncoder().encodeToString(signatureBytes));
    }
}
