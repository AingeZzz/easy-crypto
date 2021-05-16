package com.ainge.easycrypto.jose.jwe;


import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;

/**
 * JWE是一套标准，可以选择一套算法的组合
 * 这里选择：
 * 对称加密为---AES（128/192/256）-GCM---
 * 非对称加密为----RSA-OAEP---
 * <p>
 * Created by Ainge on 2019/11/24
 */
public class JsonWebEncryption {

    /**
     * 私钥
     */
    private byte[] privateKey;
    /**
     * 公钥
     */
    private byte[] publicKey;
    /**
     * 原文plaintext
     */
    private byte[] plaintext;

    /**
     * JWE标准化对象
     */
    private JweCompactObject jweCompactObject;

    public JsonWebEncryption(String compactSerialization, byte[] privateKey) {
        this.jweCompactObject = new JweCompactObject(compactSerialization);
        this.privateKey = privateKey;
    }

    public JsonWebEncryption(byte[] plaintext, byte[] publicKey) {
        this.plaintext = plaintext;
        this.publicKey = publicKey;
    }

    public String getJWEContent() {
        if (this.jweCompactObject == null) {
            try {
                this.encrypt();
            } catch (Exception e) {
                throw new JweException("encrypt error" + e.getMessage());
            }
        }
        return this.jweCompactObject.toJweContent();
    }

    /**
     * 获取ciphertext解密后的内容
     *
     * @return
     */
    public byte[] getPlaintextBytes() {
        if (this.plaintext == null) {
            try {
                this.decrypt();
            } catch (Exception e) {
                throw new JweException("decrypt error: " + e.getMessage());
            }
        }
        return this.plaintext;
    }

    private void encrypt() throws Exception {
        if (this.plaintext == null) {
            throw new IllegalArgumentException();
        }
        if (this.publicKey == null) {
            throw new IllegalArgumentException("encrypt need set public key");
        }
        if (this.jweCompactObject == null) {
            byte[] iv = randomBytes(AESCoder.IV_BYTE_LENGTH);
            byte[] cek = randomBytes(AESCoder.AES_256_KEY_LENGTH);

            byte[] encryptByPublicKey = RSACoder.encryptByPublicKey(cek, this.publicKey);
            byte[] ciphertext = AESCoder.AesGcmEncrypt(this.plaintext, iv, cek, null, JweCompactObject.getAAD());
            // （ciphertext[]长度为len，[0,len - tagLen]，[len - tagLen,len],前者为真正的密文，后面为tag认证数据）
            int len = ciphertext.length - AESCoder.TAG_BYTE_LENGTH;
            byte[] subCiphertext = new byte[len];
            System.arraycopy(ciphertext, 0, subCiphertext, 0, len);
            byte[] tag = new byte[AESCoder.TAG_BYTE_LENGTH];
            System.arraycopy(ciphertext, len, tag, 0, AESCoder.TAG_BYTE_LENGTH);
            this.jweCompactObject = new JweCompactObject(encryptByPublicKey, iv, subCiphertext, tag);
        }
    }

    private void decrypt() throws Exception {
        if (this.jweCompactObject == null) {
            throw new IllegalArgumentException();
        }
        if (this.privateKey == null) {
            throw new IllegalArgumentException("decrypt need set private key");
        }
        // aes解密需要的 key
        byte[] cek = RSACoder.decryptByPrivateKey(jweCompactObject.getEncryptedKey(), this.privateKey);
        // TODO: jwe中有说，如果header有zip字段，需要根据压缩算法来解压缩
        // decrypted = decompress(getHeaders(), decrypted);
        this.plaintext = AESCoder.AesGcmDecrypt(jweCompactObject.getCiphertext(), jweCompactObject.getIv(), cek, jweCompactObject.getAuthTag(), jweCompactObject.getAAD());
    }


    public String getPlaintextAsUtf8String() {
        return new String(getPlaintextBytes(), StandardCharsets.UTF_8);
    }

    public static byte[] randomBytes(int length, SecureRandom secureRandom) {
        secureRandom = Optional.ofNullable(secureRandom).orElseGet(SecureRandom::new);
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public static byte[] randomBytes(int length) {
        return randomBytes(length, null);
    }

    private static class AESCoder {
        private static final int IV_BYTE_LENGTH = 12;
        private static final int TAG_BYTE_LENGTH = 16;
        private static final int AES_256_KEY_LENGTH = 32;

        public static byte[] AesGcmDecrypt(byte[] ciphertext, byte[] iv, byte[] key, byte[] tag, byte[] aad) throws Exception {
            checkAesKey(key);
            // 还原密钥
            Key k = new SecretKeySpec(key, "AES");
            // 获取AES-GCM-NoPadding模式的Cipher
            int tagBitLength = Optional.ofNullable(tag).map(t -> t.length).orElse(0);
            Cipher initialisedCipher = getInitialisedAesGcmCipher(k, tagBitLength, iv, Cipher.DECRYPT_MODE);
            if (aad != null && aad.length > 0) {
                initialisedCipher.updateAAD(aad);
            }
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byteArrayOutputStream.write(ciphertext);
            if (tag != null && tag.length > 0) {
                byteArrayOutputStream.write(tag);
            }
            return initialisedCipher.doFinal(byteArrayOutputStream.toByteArray());
        }

        public static byte[] AesGcmEncrypt(byte[] ciphertext, byte[] iv, byte[] key, byte[] tag, byte[] aad) throws Exception {
            checkAesKey(key);
            // 还原密钥
            Key k = new SecretKeySpec(key, "AES");
            // 获取AES-GCM-NoPadding模式的Cipher
            int tagBitLength = Optional.ofNullable(tag).map(t -> t.length).orElse(TAG_BYTE_LENGTH);
            Cipher initialisedCipher = getInitialisedAesGcmCipher(k, tagBitLength, iv, Cipher.ENCRYPT_MODE);
            if (aad != null && aad.length > 0) {
                String s = Hex.encodeHexString(aad);
                System.out.println(s);
                initialisedCipher.updateAAD(aad);
            }
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byteArrayOutputStream.write(ciphertext);
            if (tag != null && tag.length > 0) {
                byteArrayOutputStream.write(tag);
            }
            return initialisedCipher.doFinal(byteArrayOutputStream.toByteArray());
        }

        private static void checkAesKey(byte[] key) throws InvalidKeyException {
            if (key == null) {
                throw new InvalidKeyException("key empty");
            }
            if (key.length == 16 || key.length == 24 || key.length == 32) {
                return;
            }
            throw new InvalidKeyException("key length error,must be 16 or 24 or 32");
        }


        /**
         * 获取cipher
         *
         * @param key          对称密钥
         * @param tagBitLength 认证标签T的长度（位）
         * @param iv           iv向量
         * @param mode         加密模式（1）或者解密模式（2）
         * @return
         * @throws Exception
         */
        private static Cipher getInitialisedAesGcmCipher(Key key, int tagBitLength, byte[] iv, int mode) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            try {
                /**
                 * tLen：认证标签T的长度（位），一个字节8位
                 */
                GCMParameterSpec parameterSpec = new GCMParameterSpec(tagBitLength * 8, iv);
                cipher.init(mode, key, parameterSpec);
                return cipher;
            } catch (InvalidKeyException e) {
                throw new Exception("Invalid key for " + "AES/GCM/NoPadding", e);
            } catch (InvalidAlgorithmParameterException e) {
                throw new Exception(e.toString(), e);
            }
        }


    }

    private static class RSACoder {

        /**
         * 私钥解密
         *
         * @param data 待解密数据
         * @return byte[] 解密数据
         * @throws Exception
         */
        public static byte[] decryptByPrivateKey(byte[] data, byte[] key) throws Exception {

            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            // 生成私钥
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

            // RSA/ECB/OAEPWithSHA-1AndMGF1Padding
            Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
            oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
            return oaepFromInit.doFinal(data);
        }

        /**
         * RSA公钥加密
         * 受限于运算效率和明文长度，一般只用于加密对称密钥，真正的数据加密采用对称加密
         *
         * @param data          明文 ，一般为对称密钥
         * @param publicKeyData 公钥
         * @return 密文
         */
        public static byte[] encryptByPublicKey(byte[] data, byte[] publicKeyData) throws Exception {
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyData);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            // 生成公钥
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            // RSA/ECB/OAEPWithSHA-1AndMGF1Padding
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec parameterSpec = new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, parameterSpec);
            return cipher.doFinal(data);
        }
    }
}
