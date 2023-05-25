package HW02;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class Decrypt {

    //from vault (в реальном примере крайне желательно хранение в конфигах)
    private static final String SECRET_KEY = "myverysecretkey";
    //from vault
    private static final String INIT_VECTOR = "mysecretvector";

    private static final int KEY_LENGTH = 256;
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    public static final String AES = "AES";

    public static String getHashSum(String str) {
        return getHashSumBySHA(str);
    }

    public static String decryptWithAESCipher(String encrypted) {
        try {
            Cipher cipher = getAESCipher(Cipher.DECRYPT_MODE);
            // Декодируем зашифрованную строку из base64 и расшифровываем данные
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.out.println("Не удалось расшифровать по причине: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static String encryptWithAESCipher(String str) {
        try {
            Cipher cipher = getAESCipher(Cipher.ENCRYPT_MODE);
            // Шифруем данные
            byte[] encryptedBytes = cipher.doFinal(str.getBytes(StandardCharsets.UTF_8));
            // Кодируем зашифрованную строку в base64
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            System.out.println("Не удалось зашифровать по причине: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private static String getHashSumBySHA(String str) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] newHash = md.digest(str.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(newHash);
        } catch (Exception e) {
            System.out.println("Не удалось рассчитать хэш слова по причине: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private static Cipher getAESCipher(int cipherMode) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(KEY_LENGTH);

        // Получаем ключ и вектор инициализации
        byte[] bytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        SecretKey key = new SecretKeySpec(Arrays.copyOf(bytes, 16), AES);

        byte[] ivBytes = INIT_VECTOR.getBytes(StandardCharsets.UTF_8);
        IvParameterSpec iv = new IvParameterSpec(Arrays.copyOf(ivBytes, 16));

        // Создаем объект Cipher для шифрования данных
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(cipherMode, key, iv);
        return cipher;
    }
}
