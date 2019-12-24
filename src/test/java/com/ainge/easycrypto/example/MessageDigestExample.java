package com.ainge.easycrypto.example;

import com.ainge.easycrypto.digest.HMacCrypter;
import com.ainge.easycrypto.digest.MessageDigestCrypter;
import com.ainge.easycrypto.util.ByteUtil;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;


/**
 * 消息摘要实现例子
 *
 * @author: Ainge
 * @Time: 2019/12/21 22:04
 */
public class MessageDigestExample extends InstallBCSupport {


    @Test
    public void messageDigest() throws Exception {

        byte[] data = "消息摘要原文".getBytes("utf-8");
        byte[] md5s = MessageDigestCrypter.computeDigest("MD5", data);
        byte[] md5s1 = MessageDigestCrypter.calculateDigest("MD5", data);
        Assert.assertArrayEquals(md5s, md5s1);

        byte[] sha1 = MessageDigestCrypter.computeDigest("SHA-1", data);
        byte[] sha11 = MessageDigestCrypter.calculateDigest("SHA-1", data);
        Assert.assertArrayEquals(sha1, sha11);

        byte[] sha256 = MessageDigestCrypter.computeDigest("SHA-256", data);
        byte[] sha256_1 = MessageDigestCrypter.calculateDigest("SHA-256", data);
        Assert.assertArrayEquals(sha256, sha256_1);

    }

    @Test
    public void hmacTest() throws Exception {
        SecretKey aes = HMacCrypter.toHMacKey(ByteUtil.randomBytes(16), "AES");
        byte[] HmacSHA256 = HMacCrypter.computeMac("HmacSHA256", aes, "123456".getBytes("UTF-8"));
    }



}
