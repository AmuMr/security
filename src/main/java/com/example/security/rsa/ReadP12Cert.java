package com.example.security.rsa;

import org.apache.commons.codec.binary.Base64;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class ReadP12Cert {
    public static void main(String[] args) {
        final String KEYSTORE_FILE = "/Users/sky/Downloads/hxf0405_private.p12";
        final String KEYSTORE_PASSWORD = "123456";

        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream(KEYSTORE_FILE);

            // If the keystore password is empty(""), then we have to set
            // to null, otherwise it won't work!!!
            char[] nPassword = null;
            if ((KEYSTORE_PASSWORD == null) || KEYSTORE_PASSWORD.trim().equals("")) {
                nPassword = null;
            } else {
                nPassword = KEYSTORE_PASSWORD.toCharArray();
            }
            ks.load(fis, nPassword);
            fis.close();

            System.out.println("keystore type=" + ks.getType());

            // Now we loop all the aliases, we need the alias to get keys.
            // It seems that this value is the "Friendly name" field in the
            // detals tab <-- Certificate window <-- view <-- Certificate
            // Button <-- Content tab <-- Internet Options <-- Tools menu
            // In MS IE 6.
            Enumeration enums = ks.aliases();
            String keyAlias = "hxf0405";
            if (enums.hasMoreElements()) // we are readin just one certificate.
            {
                keyAlias = (String) enums.nextElement();
                System.out.println("alias=[" + keyAlias + "]");
            }

            // Now once we know the alias, we could get the keys.
            System.out.println("is key entry=" + ks.isKeyEntry(keyAlias));
            PrivateKey prikey = (PrivateKey) ks.getKey(keyAlias, nPassword);
            Certificate cert = ks.getCertificate(keyAlias);
            PublicKey pubkey = cert.getPublicKey();

            System.out.println("cert class = " + cert.getClass().getName());
            System.out.println("cert = " + cert);
            System.out.println("public key = " + Base64.encodeBase64String(pubkey.getEncoded()) );
            System.out.println("private key = " + Base64.encodeBase64String(prikey.getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}