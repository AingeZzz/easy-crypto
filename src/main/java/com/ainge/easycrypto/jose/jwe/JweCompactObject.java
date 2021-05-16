package com.ainge.easycrypto.jose.jwe;


import org.apache.commons.codec.binary.Base64;

import java.nio.charset.StandardCharsets;

/**
 * BASE64URL(UTF8(JWE Protected Header)) || '.' ||
 * BASE64URL(JWE Encrypted Key) || '.' ||
 * BASE64URL(JWE Initialization Vector) || '.' ||
 * BASE64URL(JWE Ciphertext) || '.' ||
 * BASE64URL(JWE Authentication Tag)
 * <p>
 * <p>
 * Created by Ainge on 2019/11/24
 */
public class JweCompactObject {
    /**
     * 协商好算法直接写死了
     */
    public static final String defaultHeaders = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}";
    /**
     * Base64不带换行符
     */
    public static final String base64Headers = Base64.encodeBase64URLSafeString(defaultHeaders.getBytes(StandardCharsets.UTF_8));
    /**
     * 双方约定好
     */
    public static final byte[] defaultAAD = base64Headers.getBytes(StandardCharsets.US_ASCII);

    /**
     * AES的对称密钥，用于解密
     */
    private byte[] encryptedKey;

    /**
     * IV向量，用于解密
     */
    private byte[] iv;

    /**
     * 密文，真正传输的数据
     */
    private byte[] ciphertext;

    /**
     * Authentication Tag 用于验证
     */
    private byte[] authTag;

    public JweCompactObject(String compactSerialization) {

        if (compactSerialization == null || compactSerialization.trim().isEmpty()) {
            throw new IllegalArgumentException("compactSerialization");
        }
        String[] deserialize = CompactSerializer.deserialize(compactSerialization);
        if (deserialize.length != 5) {
            throw new IllegalArgumentException("JweCompactObject deserialize error ...");
        }
        // 有些base64编码带换行符的,加密的时候不要带上换行符到add数据中
        if(!base64Headers.equalsIgnoreCase(deserialize[0])){
            throw new IllegalArgumentException("header error");
        }
        this.encryptedKey = Base64.decodeBase64(deserialize[1]);
        this.iv = Base64.decodeBase64(deserialize[2]);
        this.ciphertext = Base64.decodeBase64(deserialize[3]);
        this.authTag = Base64.decodeBase64(deserialize[4]);
    }


    public JweCompactObject(byte[] encryptedKey, byte[] iv, byte[] ciphertext, byte[] authTag) {
        this.encryptedKey = encryptedKey;
        this.iv = iv;
        this.ciphertext = ciphertext;
        this.authTag = authTag;
    }

    public String toJweContent() {
        return CompactSerializer.serialize(base64Headers,
                Base64.encodeBase64URLSafeString(encryptedKey),
                Base64.encodeBase64URLSafeString(iv),
                Base64.encodeBase64URLSafeString(ciphertext),
                Base64.encodeBase64URLSafeString(authTag));
    }


    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    public byte[] getIv() {
        return iv;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public byte[] getAuthTag() {
        return authTag;
    }

    public static byte[] getAAD() {
        // jwe标准有说，AES-GCM模式的话，这个aad要为：Base64url(headers).toASCII();
        return defaultAAD;
    }
}
