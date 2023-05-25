package HW05;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Base64;

public class DecryptApp {
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Необходимо указать 3 параметра - путь к хранилищу, имя ключа и зашифрованную строку");
            return;
        }

        String keyStorePath = args[0];
        String keyName = args[1];
        String encryptedString = new String(Base64.getDecoder().decode(args[2]));

        try (FileInputStream fileInputStream = new FileInputStream(keyStorePath)) {

            char[] password = "password".toCharArray();

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(fileInputStream, password);

            KeyStore.ProtectionParameter passwordProtection = new KeyStore.PasswordProtection(password);
            KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyName, passwordProtection);
            PrivateKey privateKey = keyEntry.getPrivateKey();

            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decrypted = cipher.doFinal(encryptedString.getBytes());
            String decryptedString = new String(decrypted);

            System.out.println("Расшифрованнный текст: " + decryptedString);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
