package com.ainge.easycrypto.generators;

import com.ainge.easycrypto.exception.CryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author: Ainge
 * 2019/12/2 17:21
 */
public class RSAKeyPairGenerator {

    private static final String ALGORITHM = "RSA";

    /**
     * 产生RSA密钥对
     *
     * @param keySize 密钥对长度，一般为2048,1024
     * @return
     */
    public static KeyPair generateRSAKeyPair(int keySize) throws CryptoException {
        try {
            // create the keys
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            generator.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e.getMessage(), e);
        } catch (NoSuchProviderException e) {
            throw new CryptoException(e.getMessage(), e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    /**
     * 转为pkcs8私钥
     *
     * @param pkcs8PrivateKey
     * @return
     */
    public static PrivateKey converPKCS8(byte[] pkcs8PrivateKey) throws CryptoException {
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(pkcs8PrivateKey);
        KeyFactory keyFact = null;
        try {
            keyFact = KeyFactory.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            return keyFact.generatePrivate(pkcs8Spec);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e.getMessage(), e);
        } catch (NoSuchProviderException e) {
            throw new CryptoException(e.getMessage(), e);
        } catch (InvalidKeySpecException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }


    /**
     * 转为x509公钥
     *
     * @param x509PublicKey
     * @return
     */
    public static PublicKey converX509(byte[] x509PublicKey) throws CryptoException {
        if (x509PublicKey == null || x509PublicKey.length == 0) {
            throw new IllegalArgumentException("x509PublicKey empty");
        }
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(x509PublicKey);
        try {
            KeyFactory keyFact = KeyFactory.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            return keyFact.generatePublic(x509Spec);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e.getMessage(), e);
        } catch (NoSuchProviderException e) {
            throw new CryptoException(e.getMessage(), e);
        } catch (InvalidKeySpecException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

}
