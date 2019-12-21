package com.ainge.easycrypto.digest;

import com.ainge.easycrypto.exception.CryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * MAC算法结合了MD5和SHA算法的优势，并加入了密钥的支持，是一种更为安全的消息摘要算法
 * 通常也把MAC成为HMAC(keyed-Hash Message Authentication Code)
 *
 * @author: Ainge
 * @Time: 2019/12/21 16:19
 */
public class HMacCrypter {

    /**
     * 计算mac值
     *
     * @param algorithm mac算法名称
     * @param key       一个适合mac算法名称的key
     * @param data      数据
     * @return mac值.
     */
    public static byte[] computeMac(String algorithm, SecretKey key, byte[] data) throws CryptoException {
        try {
            Mac mac = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            mac.init(key);
            mac.update(data);
            return mac.doFinal();
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }

    }

    /**
     * @param keyBytes 必须为128/192/256位，也就是字节长度位16/24/32
     * @return
     */
    public static SecretKey toAESKey(byte[] keyBytes) {
        return toHMacKey(keyBytes, "AES");
    }

    /**
     * @param keyBytes  密钥字节
     * @param algorithm 算法，例如：HMacSHA256
     * @return
     */
    public static SecretKey toHMacKey(byte[] keyBytes, String algorithm) {

        return new SecretKeySpec(keyBytes, algorithm);
    }
}
