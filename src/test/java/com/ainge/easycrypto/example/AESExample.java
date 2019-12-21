package com.ainge.easycrypto.example;

import com.ainge.easycrypto.sysmmetric.AESCrypter;
import com.ainge.easycrypto.util.ByteUtil;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author: Ainge
 * @Time: 2019/12/21 22:10
 */
public class AESExample extends InstallBCSupport {


    @Test
    public void aesCbc() throws Exception {
        byte[] keyBytes = ByteUtil.randomBytes(16); //16*8 = 128bits
        byte[] iv = ByteUtil.randomBytes(16); // IV must be 16 bytes long.
        byte[] plaintext = "我就是原文".getBytes("utf-8");
        // aes_128_cbc 加密
        byte[] ciphertext = AESCrypter.cbcEncrypt(keyBytes, iv, plaintext);

        // aes_128_cbc 解密
        byte[] decrypt = AESCrypter.cbcDecrypt(keyBytes, iv, ciphertext);

        // 验证数据
        Assert.assertArrayEquals(plaintext, decrypt);
    }

    @Test
    public void aesGcm() throws Exception {
        byte[] keyBytes = ByteUtil.randomBytes(16); //16*8 = 128bits
        byte[] iv = ByteUtil.randomBytes(16); // IV must be 16 bytes long.
        byte[] plaintext = "我就是原文".getBytes("utf-8");
        int tagLength = 16;
        // 附加到认证信息，一般双方约定，或者明文传输
        byte[] aad = "ip=127.0.0.1".getBytes("utf-8");
        // （ciphertext[]长度为len，[0,len - tagLen]，[len - tagLen,len],前者为真正的密文，后面为tag认证数据）
        byte[] ciphertext = AESCrypter.gcmEncrypt(keyBytes, iv, tagLength, plaintext);
        // 解密
        byte[] encrypt = AESCrypter.gcmDecrypt(keyBytes, iv, tagLength, ciphertext);
        Assert.assertArrayEquals(plaintext, encrypt);
    }


    @Test
    public void aesGcmWithAAD() throws Exception {
        byte[] keyBytes = ByteUtil.randomBytes(16); //16*8 = 128bits
        byte[] iv = ByteUtil.randomBytes(16); // IV must be 16 bytes long.
        byte[] plaintext = "我就是原文".getBytes("utf-8");
        int tagLength = 16;
        // 附加到认证信息，一般双方约定，或者明文传输
        byte[] aad = "ip=127.0.0.1".getBytes("utf-8");
        // （ciphertext[]长度为len，[0,len - tagLen]，[len - tagLen,len],前者为真正的密文，后面为tag认证数据）
        byte[] ciphertext = AESCrypter.gcmEncryptWithAAD(keyBytes, iv, tagLength, plaintext, aad);
        // 解密
        byte[] encrypt = AESCrypter.gcmDecryptWithAAD(keyBytes, iv, tagLength, ciphertext, aad);
        Assert.assertArrayEquals(plaintext, encrypt);
    }


}
