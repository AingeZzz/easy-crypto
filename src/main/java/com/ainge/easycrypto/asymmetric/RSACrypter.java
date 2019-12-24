package com.ainge.easycrypto.asymmetric;


import com.ainge.easycrypto.exception.RSACryptoException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;

/**
 * 这里只实现了RSA，公钥加密，私钥解密的用途
 *
 * @author: Ainge
 */
public class RSACrypter {

    /**
     * 私钥解密
     *
     * @param data       密文，一般为对称密钥的key
     * @param privateKey 私钥
     * @return 明文
     */
    public static byte[] decryptByRsaOaep(byte[] data, PrivateKey privateKey) throws RSACryptoException {
        try {
            // RSA/ECB/OAEPWithSHA-1AndMGF1Padding
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding", "BC");
            OAEPParameterSpec parameterSpec = new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, parameterSpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RSACryptoException(e.getMessage(), e);
        }
    }

    /**
     * RSA公钥加密
     * 受限于运算效率和明文长度，一般只用于加密对称密钥，真正的数据加密采用对称加密
     *
     * @param data      明文 ，一般为对称密钥
     * @param publicKey 公钥
     * @return 密文
     */
    public static byte[] encryptByRsaOaep(byte[] data, PublicKey publicKey) throws RSACryptoException {
        try {
            // RSA/ECB/OAEPWithSHA-1AndMGF1Padding
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding", "BC");
            OAEPParameterSpec parameterSpec = new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, parameterSpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RSACryptoException(e.getMessage(), e);
        }
    }


    /**
     * 包装密钥
     *
     * @param rsaPublic rsa公钥用于包装
     * @param secretKey 要加密/包装的密钥
     * @return 返回加密/包装后的密钥
     * @throws GeneralSecurityException 包装失败则抛出异常
     */
    public static byte[] keyWrapOAEP(PublicKey rsaPublic, SecretKey secretKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding", "BC");
        cipher.init(Cipher.WRAP_MODE, rsaPublic);
        return cipher.wrap(secretKey);
    }


    /**
     * 还原被加密/包装的wrappedKey
     *
     * @param rsaPrivate   RSA私钥
     * @param wrappedKey   加密/包装后的密钥
     * @param keyAlgorithm wrappedKey用于的算法
     * @return the unwrapped SecretKey.
     * @throws GeneralSecurityException 失败则抛出异常
     */
    public static SecretKey keyUnwrapOAEP(PrivateKey rsaPrivate, byte[] wrappedKey, String keyAlgorithm) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding", "BC");
        cipher.init(Cipher.UNWRAP_MODE, rsaPrivate);
        return (SecretKey) cipher.unwrap(wrappedKey, keyAlgorithm, Cipher.SECRET_KEY);
    }

    /**
     * Generate a wrapped key using the RSA OAEP algorithm according
     * to the passed in OAEPParameterSpec and return the resulting encryption.
     *
     * @param rsaPublic the public key to base the wrapping on.
     * @param oaepSpec  the parameter specification for the OAEP operation.
     * @param secretKey the secret key to be encrypted/wrapped.
     * @return true if the signature verifies, false otherwise.
     */
    public static byte[] keyWrapOAEP(PublicKey rsaPublic, OAEPParameterSpec oaepSpec, SecretKey secretKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        cipher.init(Cipher.WRAP_MODE, rsaPublic, oaepSpec);
        return cipher.wrap(secretKey);
    }

    /**
     * Return the secret key that was encrypted in wrappedKey.
     *
     * @param rsaPrivate   the private key to use for the unwrap.
     * @param oaepSpec     the parameter specification for the OAEP operation.
     * @param wrappedKey   the encrypted secret key.
     * @param keyAlgorithm the algorithm that the encrypted key is for.
     * @return the unwrapped SecretKey.
     */
    public static SecretKey keyUnwrapOAEP(PrivateKey rsaPrivate, OAEPParameterSpec oaepSpec, byte[] wrappedKey, String keyAlgorithm) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        cipher.init(Cipher.UNWRAP_MODE, rsaPrivate, oaepSpec);
        return (SecretKey) cipher.unwrap(wrappedKey, keyAlgorithm, Cipher.SECRET_KEY);
    }


}
