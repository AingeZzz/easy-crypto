package com.ainge.easycrypto.keystore;

import com.ainge.easycrypto.exception.CryptoException;
import com.ainge.easycrypto.exception.UncheckedException;

import javax.security.auth.x500.X500PrivateCredential;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * 证书库的一些简单操作
 *
 * @author: Ainge
 * @Time: 2019/12/26 22:20
 */
public class KeyStoreUtils {


    /**
     * 将证书和私钥包装为X500PrivateCredential对象
     *
     * @param cert 证书对象
     * @param key  私钥
     * @return an X500PrivateCredential containing the key and its certificate.
     */
    public static X500PrivateCredential convertX509Certificate(X509Certificate cert, PrivateKey key) {
        return new X500PrivateCredential(cert, key);
    }


    /**
     * 从证书库加载证书，证书链，私钥。
     *
     * @param alias
     * @param keyPwd
     * @param storePwd
     * @param fileName
     * @return KeyStoreCertInfos
     * @throws CryptoException
     */
    public static KeyStoreCertInfos getKeyStoreFromJKS(String alias, String keyPwd, String storePwd, String fileName) throws CryptoException {
        return load(KeyStoreType.JKS,alias,keyPwd,storePwd,fileName);
    }

    /**
     * 从证书库加载证书，证书链，私钥。
     *
     * @param alias
     * @param keyPwd
     * @param storePwd
     * @param fileName
     * @return KeyStoreCertInfos
     * @throws CryptoException
     */
    public static KeyStoreCertInfos getKeyStoreFromPKCS12(String alias, String keyPwd, String storePwd, String fileName) throws CryptoException {
        return load(KeyStoreType.PKCS12,alias,keyPwd,storePwd,fileName);
    }


    /**
     * 从证书库加载证书，证书链，私钥。
     *
     * @param type
     * @param alias
     * @param keyPwd
     * @param storePwd
     * @param fileName
     * @return
     * @throws CryptoException
     */
    public static KeyStoreCertInfos load(KeyStoreType type, String alias, String keyPwd, String storePwd, String fileName) throws CryptoException {
        FileInputStream fileInputStream = null;
        try {
            fileInputStream = new FileInputStream(fileName);
            KeyStore store = KeyStore.getInstance(type.name(), "BC");
            store.load(fileInputStream, storePwd == null ? null : storePwd.toCharArray());

            if (!store.containsAlias(alias)) {
                throw new CryptoException("the alias=" + alias + " not exists in this keystore");
            }

            Certificate certificate = store.getCertificate(alias);
            Certificate[] chain = store.getCertificateChain(alias);
            Key privateKey = store.getKey(alias, keyPwd == null ? null : keyPwd.toCharArray());
            return new KeyStoreCertInfos(certificate, chain, privateKey);
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (IOException e) {
                    throw new UncheckedException("IOException fileName=" + fileName, e);
                }
            }
        }

    }


    /**
     * 产生JKS证书库文件
     *
     * @param cred     包含证书和私钥的X500PrivateCredential对象
     * @param chain    证书链
     * @param alias    证书别名
     * @param keyPwd   证书私钥访问密码
     * @param storePwd 证书库访问密码
     * @param fileName 保存证书库的文件名
     * @throws CryptoException
     */
    public static void generateJKS(X500PrivateCredential cred, Certificate[] chain, String alias,
                                   String keyPwd, String storePwd, String fileName) throws CryptoException {
        try {
            generateKeyStoreFile(cred, chain, KeyStoreType.JKS, alias, keyPwd, storePwd, fileName);
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    /**
     * 产生pfx12证书库文件
     *
     * @param cred     包含证书和私钥的X500PrivateCredential对象
     * @param chain    证书链
     * @param alias    证书别名
     * @param keyPwd   证书私钥访问密码
     * @param storePwd 证书库访问密码
     * @param fileName 保存证书库的文件名
     * @throws CryptoException
     */
    public static void generatePfx12(X500PrivateCredential cred, Certificate[] chain, String alias,
                                     String keyPwd, String storePwd, String fileName) throws CryptoException {
        try {
            generateKeyStoreFile(cred, chain, KeyStoreType.PKCS12, alias, keyPwd, storePwd, fileName);
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    /**
     * 产生证书库文件
     *
     * @param cred     包含证书和私钥的X500PrivateCredential对象
     * @param chain    证书链
     * @param type     证书库类型（目前只支持jks，pfx12）
     * @param alias    证书别名
     * @param keyPwd   证书私钥访问密码
     * @param storePwd 证书库访问密码
     * @param fileName 保存证书库的文件名
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws NoSuchProviderException
     */
    public static void generateKeyStoreFile(X500PrivateCredential cred, Certificate[] chain, KeyStoreType type,
                                            String alias, String keyPwd, String storePwd, String fileName)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
        KeyStore store = KeyStore.getInstance(type.name(), "BC");
        store.load(null, null);
        store.setKeyEntry(alias, cred.getPrivateKey(), keyPwd == null ? null : keyPwd.toCharArray(), chain);
        FileOutputStream fOut = null;
        try {
            fOut = new FileOutputStream(fileName);
            store.store(fOut, storePwd == null ? null : storePwd.toCharArray());
        } finally {
            if (fOut != null) {
                fOut.close();
            }
        }
    }

    public enum KeyStoreType {
        JKS,
        PKCS12;
    }
}
