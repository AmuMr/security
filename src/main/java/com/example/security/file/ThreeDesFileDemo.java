package com.example.security.file;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class ThreeDesFileDemo {


    public static void main(String[] args) throws Exception {
        String key = "222222222222222222222222";
        File destFile = new File("/Users/sky/Downloads/1.zip");
        File srcFile = new File("/Users/sky/Downloads/1.txt");

        encrypt(key, srcFile, destFile);
        decrypt(key, srcFile, destFile);
    }

    private static void decrypt(String key, File txtFile, File zipFile) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(zipFile);
        CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, getCipher(key, Cipher.DECRYPT_MODE));
        ZipInputStream zipInputStream = new ZipInputStream(cipherInputStream);
        if (zipInputStream.getNextEntry() == null) {
            return;
        }
        FileOutputStream fileOutputStream = new FileOutputStream(txtFile);
        BufferedInputStream bis = new BufferedInputStream(zipInputStream);
        BufferedOutputStream bos = new BufferedOutputStream(fileOutputStream);
        int len;
        byte[] bytes = new byte[2048];
        while ((len = bis.read(bytes)) != -1) {
            bos.write(bytes, 0, len);
        }
        bos.flush();
        bis.close();
        bos.close();
        fileInputStream.close();
        zipInputStream.close();
        fileOutputStream.close();
    }


    private static void encrypt(String key, File txtFile, File zipFile) throws Exception {
        FileOutputStream outputStream = new FileOutputStream(zipFile);
        OutputStream cipherOutputStream = new CipherOutputStream(outputStream, getCipher(key, Cipher.ENCRYPT_MODE));
        ZipOutputStream zipOutputStream = new ZipOutputStream(cipherOutputStream);
        zipOutputStream.putNextEntry(new ZipEntry(txtFile.getAbsolutePath()));
        FileInputStream fileInputStream = new FileInputStream(txtFile);
        BufferedInputStream bis = new BufferedInputStream(fileInputStream);
        BufferedOutputStream bos = new BufferedOutputStream(zipOutputStream);

        int len;
        byte[] bytes = new byte[2048];
        while ((len = bis.read(bytes)) != -1) {
            bos.write(bytes, 0, len);
        }
        bos.flush();
        bis.close();
        bos.close();
        zipOutputStream.close();
        outputStream.close();
        fileInputStream.close();
    }

    private static Cipher getCipher(String key, int encryptMode) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "DESede");
        Cipher cipher = Cipher.getInstance("DESede");
        cipher.init(encryptMode, secretKey);
        return cipher;
    }


}
