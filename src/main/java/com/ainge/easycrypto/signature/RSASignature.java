package com.ainge.easycrypto.signature;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PSSParameterSpec;

/**
 * @author: Ainge
 * @Time: 2019/12/21 18:38
 */
public class RSASignature {

    private static final String ALGORITHM = "SHA256withRSA";


    /**
     * 签名
     *
     * @param rsaPrivate RSA私钥
     * @param original   签名原文
     * @return 签名值
     * @throws GeneralSecurityException 签名过程失败抛出异常
     */
    public static byte[] generatePKCS1dot5Signature(PrivateKey rsaPrivate, byte[] original) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(ALGORITHM, "BC");
        signature.initSign(rsaPrivate);
        signature.update(original);
        return signature.sign();
    }


    /**
     * 验签
     *
     * @param rsaPublic    RSA公钥
     * @param original     签名原文
     * @param encSignature 签名值
     * @return 验证结果
     * @throws GeneralSecurityException 验证过程失败抛出异常
     */
    public static boolean verifyPKCS1dot5Signature(PublicKey rsaPublic, byte[] original, byte[] encSignature) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(ALGORITHM, "BC");
        signature.initVerify(rsaPublic);
        signature.update(original);
        return signature.verify(encSignature);
    }

    /**
     * 签名
     *
     * @param rsaPrivate RSA私钥
     * @param original   签名原文
     * @return 签名值
     * @throws GeneralSecurityException 签名过程失败抛出异常
     */
    public static byte[] generateRSAPSSSignature(PrivateKey rsaPrivate, byte[] original) throws GeneralSecurityException {
        // 默认SHA256withRSAandMGF1算法
        Signature signature = Signature.getInstance("SHA256withRSAandMGF1", "BC");
        signature.initSign(rsaPrivate);
        signature.update(original);
        return signature.sign();
    }

    /**
     * 验签
     *
     * @param rsaPublic    RSA公钥
     * @param original     签名原文
     * @param encSignature 签名值
     * @return 验证结果
     * @throws GeneralSecurityException 验证过程失败抛出异常
     */
    public static boolean verifyRSAPSSSignature(PublicKey rsaPublic, byte[] original, byte[] encSignature) throws GeneralSecurityException {
        // 默认SHA256withRSAandMGF1算法
        Signature signature = Signature.getInstance("SHA256withRSAandMGF1", "BC");
        signature.initVerify(rsaPublic);
        signature.update(original);
        return signature.verify(encSignature);
    }

    /**
     * 签名
     *
     * @param rsaPrivate RSA私钥
     * @param pssSpec    pssSpec
     * @param original
     * @return 签名值
     * @throws GeneralSecurityException 签名过程失败抛出异常
     */
    public static byte[] generateRSAPSSSignature(PrivateKey rsaPrivate, PSSParameterSpec pssSpec, byte[] original) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("RSAPSS", "BC");
        signature.setParameter(pssSpec);
        signature.initSign(rsaPrivate);
        signature.update(original);
        return signature.sign();
    }


    /**
     * 验签
     *
     * @param rsaPublic    RSA公钥
     * @param pssSpec      pssSpec
     * @param original     签名原文
     * @param encSignature 签名值
     * @return 验证结果
     * @throws GeneralSecurityException 验证过程失败抛出异常
     */
    public static boolean verifyRSAPSSSignature(PublicKey rsaPublic, PSSParameterSpec pssSpec, byte[] original, byte[] encSignature) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("RSAPSS", "BC");
        signature.setParameter(pssSpec);
        signature.initVerify(rsaPublic);
        signature.update(original);
        return signature.verify(encSignature);
    }


}
