package HW02;

public class WordEncryptor {
    public static void main(String[] args) {
        // Получаем строку для шифрования
        String str = args[0];

        // Шифруем данные
        String encryptedStr = Decrypt.encryptWithAESCipher(str);
        System.out.println("Encrypted string: " + encryptedStr);

        // Вычисляем и выводим хеш-сумму исходной строки
        System.out.println("Hash: " + Decrypt.getHashSum(str));
    }
}
