package com.ainge.easycrypto.sysmmetric;

import com.ainge.easycrypto.exception.AESCryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

/**
 * @author: Ainge
 */
public class AESCrypter {

    private static final String GCM_TRANSFORMATION_NAME = "AES/GCM/NoPadding";
    private static final String CBC_TRANSFORMATION_NAME = "AES/CBC/PKCS7Padding";

    /**
     * AES/CBC/PKCS7Padding 加密
     *
     * @param keyBytes  AES key，128 192 256 bits
     * @param iv        AES CBC 的IV向量
     * @param plaintext 需要加密的明文
     * @return 返回密文
     */
    public static byte[] cbcEncrypt(byte[] keyBytes, byte[] iv, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(CBC_TRANSFORMATION_NAME, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, toAesKey(keyBytes), new IvParameterSpec(iv));
            return cipher.doFinal(plaintext);
        } catch (InvalidKeyException e) {
            throw new AESCryptoException(e.getMessage(), e);
        } catch (Exception e) {
            throw new AESCryptoException(e.getMessage(), e);
        }
    }

    /**
     * AES/CBC/PKCS7Padding 解密
     *
     * @param keyBytes   密钥长度
     * @param iv         iv向量
     * @param ciphertext 密文
     * @return 返回明文
     */
    public static byte[] cbcDecrypt(byte[] keyBytes, byte[] iv, byte[] ciphertext) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(CBC_TRANSFORMATION_NAME, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, toAesKey(keyBytes), new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        } catch (InvalidKeyException e) {
            throw new AESCryptoException(e.getMessage(), e);
        } catch (Exception e) {
            throw new AESCryptoException(e.getMessage(), e);
        }
    }

    /**
     * 用GCM模式加密
     *
     * @param keyBytes AES密钥，一般为128,192,256 bits
     * @param iv       IV向量
     * @param tagLen   GCM模式产生的MAC值的长度
     * @param pText    明文
     * @return 密文（假设byte[]长度为len，[0,len - tagLen]，[len - tagLen,len],前者为真正的密文，后面为tag认证数据）
     */
    public static byte[] gcmEncrypt(byte[] keyBytes, byte[] iv, int tagLen, byte[] pText) {
        return gcmEncryptWithAAD(keyBytes, iv, tagLen, pText, null);
    }

    /**
     * 用GCM模式解密
     *
     * @param keyBytes AES密钥，一般为128,192,256 bits
     * @param iv       IV向量
     * @param tagLen   GCM模式产生的MAC值的长度
     * @param cText    密文 （假设byte[]长度为len，[0,len - tagLen]，[len - tagLen,len],前者为真正的密文，后面为tag认证数据）
     * @return 返回明文
     */
    public static byte[] gcmDecrypt(byte[] keyBytes, byte[] iv, int tagLen, byte[] cText) {
        return gcmDecryptWithAAD(keyBytes, iv, tagLen, cText, null);
    }


    /**
     * 用GCM模式加密(带附加认证信息)
     *
     * @param keyBytes AES密钥，一般为128,192,256 bits
     * @param iv       IV向量
     * @param tagLen   GCM模式产生的MAC值的长度
     * @param pText    明文
     * @param aad      附加的认证数据
     * @return 密文（假设byte[]长度为len，[0,len - tagLen]，[len - tagLen,len],前者为真正的密文，后面为tag认证数据）
     */
    public static byte[] gcmEncryptWithAAD(byte[] keyBytes, byte[] iv, int tagLen, byte[] pText, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance(GCM_TRANSFORMATION_NAME, BouncyCastleProvider.PROVIDER_NAME);
            // 数组字节个数 * 8
            GCMParameterSpec spec = new GCMParameterSpec(tagLen * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, toAesKey(keyBytes), spec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(pText);
        } catch (InvalidKeyException e) {
            throw new AESCryptoException(e.getMessage(), e);
        } catch (Exception e) {
            throw new AESCryptoException(e.getMessage(), e);
        }
    }


    /**
     * 用GCM模式解密(带附加认证信息)
     *
     * @param keyBytes AES密钥，一般为128,192,256 bits
     * @param iv       IV向量
     * @param tagLen   GCM模式产生的MAC值的长度
     * @param cText    密文 （假设byte[]长度为len，[0,len - tagLen]，[len - tagLen,len],前者为真正的密文，后面为tag认证数据）
     * @param aad      附加的认证数据
     * @return 返回明文
     */
    public static byte[] gcmDecryptWithAAD(byte[] keyBytes, byte[] iv, int tagLen, byte[] cText, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance(GCM_TRANSFORMATION_NAME, BouncyCastleProvider.PROVIDER_NAME);
            GCMParameterSpec spec = new GCMParameterSpec(tagLen * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, toAesKey(keyBytes), spec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(cText);
        } catch (InvalidKeyException e) {
            throw new AESCryptoException(e.getMessage(), e);
        } catch (Exception e) {
            throw new AESCryptoException(e.getMessage(), e);
        }
    }

    /**
     * 将二进制密码转为SecretKeySpec
     *
     * @param keyBytes 一般为16,24,32个字节（128，192,256 bits）
     * @return SecretKeySpec
     */
    private static SecretKeySpec toAesKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "AES");
    }
}
