package com.example.security.rsa;

import sun.misc.BASE64Encoder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.security.*;
import java.security.cert.Certificate;

/**
 * 从jks文件中导出私钥和证书
 */

public class ExportKey {
    private File keystoreFile;
    private String keyStoreType;
    private char[] password;
    private String alias;
    private File exportedPrivateFile;
    private File exportedPublicFile;

    public static KeyPair getPrivateKey(KeyStore keystore, String alias, char[] password) {
        try {
            Key key = keystore.getKey(alias, password);
            if (key instanceof PrivateKey) {
                Certificate cert = keystore.getCertificate(alias);
                PublicKey publicKey = cert.getPublicKey();
                return new KeyPair(publicKey, (PrivateKey) key);
            }
        } catch (UnrecoverableKeyException e) {
        } catch (NoSuchAlgorithmException e) {
        } catch (KeyStoreException e) {
        }
        return null;
    }

    public void exportPrivateKey() throws Exception {
        KeyStore keystore = KeyStore.getInstance(keyStoreType);
        BASE64Encoder encoder = new BASE64Encoder();
        keystore.load(new FileInputStream(keystoreFile), password);
        KeyPair keyPair = getPrivateKey(keystore, alias, password);
        PrivateKey privateKey = keyPair.getPrivate();
        String encoded = encoder.encode(privateKey.getEncoded());
        FileWriter fw = new FileWriter(exportedPrivateFile);
        fw.write("—–BEGIN PRIVATE KEY—–\n");
        fw.write(encoded);
        fw.write("\n");
        fw.write("—–END PRIVATE KEY—–");
        fw.close();
    }

    public void exportPublicKey() throws Exception {
        KeyStore keystore = KeyStore.getInstance(keyStoreType);
        BASE64Encoder encoder = new BASE64Encoder();
        keystore.load(new FileInputStream(keystoreFile), password);
        KeyPair keyPair = getPrivateKey(keystore, alias, password);
        PublicKey publicKey = keyPair.getPublic();
        String encoded = encoder.encode(publicKey.getEncoded());
        FileWriter fw = new FileWriter(exportedPublicFile);
        fw.write("—–BEGIN CERTIFICATE—–\n");
        fw.write(encoded);
        fw.write("\n");
        fw.write("—–END CERTIFICATE—–");
        fw.close();
    }

    /**
     *  生成jks  或者 keystore 文件
     *  keytool -genkey -alias chinaamc -keyalg RSA -keystore chinaamc.jks -keysize 2048 -validity 36500
     *  1、从JKS转换到PKCS12
     *  第一步： keytool -importkeystore -srckeystore <keystore.jks> -destkeystore <keystore.p12> -deststoretype PKCS12 \
     *     -srcstorepass <passvalue> -deststorepass <passvalue>
     * p12 导出公私钥
     * /1.生成1.key文件
     * openssl pkcs12 -in apple_payment.p12 -nocerts -nodes -out 1.key
     * //2.导出私钥
     * openssl rsa -in 1.key -out apple_pay_pri.pem
     * writing RSA key
     * //3.导出公钥
     * openssl rsa -in 1.key -pubout -out apple_pay_pub.pem

     *  2、从JKS中提取PEM证书
     *  keytool -export -rfc -alias <alias-name> -file <output-file.pem> -keystore <keystorefile.jks> -storepass <storepass>
     */
   public static void main(String args[]) throws Exception {
        ExportKey export = new ExportKey();
        export.keystoreFile = new File("/Users/sky/Downloads/chinaamc.jks");
        export.keyStoreType = "JKS";
        export.password = "123456".toCharArray();
        export.alias = "chinaamc";
        export.exportedPrivateFile = new File("/Users/sky/Downloads/chinaamc.key");
        export.exportedPublicFile = new File("/Users/sky/Downloads/chinaamc.cer");
        export.exportPrivateKey();
        export.exportPublicKey();
    }
}