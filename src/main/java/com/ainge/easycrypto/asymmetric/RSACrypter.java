package com.ainge.easycrypto.asymmetric;


import com.ainge.easycrypto.exception.RSACryptoException;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;

/**
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
    public static byte[] decryptByRsaOaep(byte[] data, PrivateKey privateKey) {
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
    public static byte[] encryptByRsaOaep(byte[] data, PublicKey publicKey) {
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


}
