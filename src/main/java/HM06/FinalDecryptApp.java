package HM06;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class FinalDecryptApp {
    public static void main(String[] args) {
        if (args.length < 5) {
            System.out.println("\"Нужно указать 5 параметров: путь к хранилищу, пароль для хранилища, зашифрованное слово, подпись, имя ключа");
            return;
        }

        String keystorePath = args[0];
        String keystorePassword = args[1];
        String encryptedWord = args[2];
        String signature = args[3];
        String keyName = args[4];

        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");

            // Открытие keystore
            loadKeyStore(keystorePath, keystorePassword, keyStore);

            // Получение приватного ключа
            PrivateKey privateKey = getPrivateKey(keystorePassword, keyName, keyStore);
            if (privateKey == null) {
                return;
            }

            // Расшифровка слова
            byte[] decryptedWord = getDecryptedWord(encryptedWord, privateKey);

            // Проверка подписи
            boolean verified = verifySignature(signature, keyName, keyStore, decryptedWord);

            // Вывод результатов
            if (verified) {
                System.out.println("Расшифрованное слово: " + new String(decryptedWord));
            } else {
                System.out.println("Сигнатура не прошла проверку");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static PrivateKey getPrivateKey(String keystorePassword, String keyName, KeyStore keyStore) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Key key = keyStore.getKey(keyName, keystorePassword.toCharArray());
        if (key == null) {
            System.out.println("Key not found");
            return null;
        }
        return (PrivateKey) key;
    }

    private static byte[] getDecryptedWord(String encryptedWord, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedWord.getBytes());
    }

    private static boolean verifySignature(String signature, String keyName, KeyStore keyStore, byte[] decryptedWord) throws KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PublicKey publicKey = keyStore.getCertificate(keyName).getPublicKey();
        Signature signatureVerifier = Signature.getInstance("SHA256withRSA");
        signatureVerifier.initVerify(publicKey);
        signatureVerifier.update(decryptedWord);
        boolean verified = signatureVerifier.verify(signature.getBytes());
        return verified;
    }

    private static void loadKeyStore(String keystorePath, String keystorePassword, KeyStore keyStore) throws IOException, NoSuchAlgorithmException, CertificateException {
        FileInputStream fis = new FileInputStream(keystorePath);
        keyStore.load(fis, keystorePassword.toCharArray());
        fis.close();
    }
}
