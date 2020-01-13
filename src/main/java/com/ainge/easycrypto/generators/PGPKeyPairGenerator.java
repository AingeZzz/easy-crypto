package com.ainge.easycrypto.generators;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Date;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * @author: Ainge
 * @Time: 2020/1/12 20:57
 */
public class PGPKeyPairGenerator {

    /**
     *  产生一对密钥环（私钥环，公钥环）
     * @param identity 用户标识，如： "Ainge(email) <zaj9404@163.com>"
     * @param passphrase 密码（保护私钥环）
     * @param masterRsaKeyPair 主密钥（RSA）
     * @param subRsaKeyPair 子密钥（如果有的话）
     * @return byte[][0]为私钥环，byte[][1]为公钥环
     * @throws PGPException
     * @throws IOException
     */
    public static byte[][] generateKeyRing(String identity, char[] passphrase,KeyPair masterRsaKeyPair,KeyPair subRsaKeyPair) throws PGPException, IOException {
        // 主密钥
        PGPKeyPair KeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, masterRsaKeyPair, new Date());
        // 摘要计算者
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator keyRingGen =
                new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, KeyPair, identity, sha1Calc, null, null,
                        new JcaPGPContentSignerBuilder(KeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
                        new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passphrase));

        if(subRsaKeyPair != null){
            // 如果存在子密钥
            PGPKeyPair sub = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, subRsaKeyPair, new Date());
            keyRingGen.addSubKey(sub);
        }

        // create an encoding of the secret key ring
        ByteArrayOutputStream secretOut = new ByteArrayOutputStream();
        keyRingGen.generateSecretKeyRing().encode(secretOut);
        secretOut.close();
        // create an encoding of the public key ring
        ByteArrayOutputStream publicOut = new ByteArrayOutputStream();
        keyRingGen.generatePublicKeyRing().encode(publicOut);
        publicOut.close();
        return new byte[][]{secretOut.toByteArray(), publicOut.toByteArray()};
    }


}
