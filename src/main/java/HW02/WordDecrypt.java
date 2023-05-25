package HW02;

public class WordDecrypt {

    public static void main(String[] args)  {
        // Получаем переданную строку для расшифровки
        String encryptedString = args[0];
        String decrypted = Decrypt.decryptWithAESCipher(encryptedString);
        // Выводим расшифрованную строку
        System.out.println("Decrypted string: " + decrypted);
        // Вычисляем хеш-сумму расшифрованной строки и выводим хеш-сумму
        System.out.println("Hash: " + Decrypt.getHashSum(decrypted));
    }
}
