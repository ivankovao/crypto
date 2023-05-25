package HW05;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.Cipher;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

public class KeyStoreApp {
    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Необходимо указать 2 параметра - путь к хранилищу и длину ключа RSA");
            return;
        }
        System.out.println("Зашифрованнный текст: " + Base64.getEncoder().encodeToString(encrypt(args)));
    }

    private static byte[] encrypt(String[] args) {
        String keyStorePath = args[0];
        int rsaKeyLength = Integer.parseInt(args[1]);

        try (FileOutputStream fileOutputStream = new FileOutputStream(keyStorePath)) {

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(rsaKeyLength);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            char[] password = "password".toCharArray();
            X509Certificate certificate = generateCert(keyPair);

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);
            keyStore.setKeyEntry("keyalias", keyPair.getPrivate(), password, new Certificate[]{certificate});
            keyStore.store(fileOutputStream, password);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            return cipher.doFinal("Java".getBytes());

        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
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
