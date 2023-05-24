package HM06;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

public class FinalEncryptApp {

    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Нужно указать 3 параметра: тип хранилища, пароль для хранилища, шифруемое слово");
            return;
        }

        String keystoreType = args[0];
        String keystorePassword = args[1];
        String wordToEncrypt = args[2];

        String keystorePath = "D:\\keystore.jks";

        try {
            KeyStore keyStore = KeyStore.getInstance(keystoreType);

            // Загрузка или создание keystore
            createOrLoadKeyStore(keystorePassword, keystorePath, keyStore);

            // Создание ключей RSA
            KeyPair keyPair = getKeyPair();

            // Получение открытого ключа и его сертификата
            PublicKey publicKey = keyPair.getPublic();
            if (!keyStore.containsAlias("mykey")) {
                keyStore.setKeyEntry("mykey", keyPair.getPrivate(), keystorePassword.toCharArray(), new Certificate[]{generateCert(keyPair)});
            }

            // Шифрование строки
            byte[] encryptedWord = getEncryptedWord(wordToEncrypt, publicKey);

            // Подписание строки
            byte[] signatureBytes = getSignatureBytes(wordToEncrypt, keyPair);

            // Сохранение keystore
            saveKeyStore(keystorePassword, keystorePath, keyStore);

            // Вывод результата
            System.out.println("Keystore type: " + keystoreType);
            System.out.println("Key name: mykey");
            System.out.println("Encrypted word: " + Base64.getEncoder().encodeToString(encryptedWord));
            System.out.println("Signature: " + Base64.getEncoder().encodeToString((signatureBytes)));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] getEncryptedWord(String wordToEncrypt, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(wordToEncrypt.getBytes());
    }

    private static byte[] getSignatureBytes(String wordToEncrypt, KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PrivateKey privateKey = keyPair.getPrivate();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(wordToEncrypt.getBytes());
        return signature.sign();
    }

    private static KeyPair getKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static void saveKeyStore(String keystorePassword, String keystorePath, KeyStore keyStore) {
        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keyStore.store(fos, keystorePassword.toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void createOrLoadKeyStore(String keystorePassword, String keystorePath, KeyStore keyStore) throws CertificateException, NoSuchAlgorithmException, IOException {
        try (FileInputStream fis = new FileInputStream(keystorePath);) {
            keyStore.load(fis, keystorePassword.toCharArray());
        } catch (Exception e) {
            keyStore.load(null, null);
        }
    }

    private static X509Certificate generateCert(KeyPair keyPair) {
        try {
            Date startDate = new Date();
            Date endDate = new Date(startDate.getTime() + 10000000L);
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
            X500Name name = new X500Name("CN=MyCert");

            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                    name,
                    serialNumber,
                    startDate,
                    endDate,
                    name,
                    SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
            );

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            return new JcaX509CertificateConverter().getCertificate(builder.build(signer));

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}