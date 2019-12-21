package com.ainge.easycrypto.signature;

import org.bouncycastle.jcajce.spec.SM2ParameterSpec;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * @author: Ainge
 * @Time: 2019/12/21 18:36
 */
public class SM2Signature {


    /**
     * SM2签名
     *
     * @param ecPrivate sm2私钥
     * @param original  原文
     * @return 签名值
     * @throws GeneralSecurityException 签名过程失败则抛出异常
     */
    public static byte[] generateSM2Signature(PrivateKey ecPrivate, byte[] original) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SM3withSM2", "BC");
        signature.initSign(ecPrivate);
        signature.update(original);
        return signature.sign();
    }


    /**
     * SM2验签
     *
     * @param ecPublic     sm2公钥
     * @param original     原文
     * @param encSignature 签名值
     * @return 验证结果
     * @throws GeneralSecurityException 验签过程失败则抛出异常
     */
    public static boolean verifySM2Signature(PublicKey ecPublic, byte[] original, byte[] encSignature) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SM3withSM2", "BC");
        signature.initVerify(ecPublic);
        signature.update(original);
        return signature.verify(encSignature);
    }


    /**
     * SM2签名
     *
     * @param ecPrivate sm2私钥
     * @param sm2Spec   sm2Spec
     * @param original  原文
     * @return 签名值
     * @throws GeneralSecurityException 签名过程失败则抛出异常
     */
    public static byte[] generateSM2Signature(
            PrivateKey ecPrivate, SM2ParameterSpec sm2Spec, byte[] original)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SM3withSM2", "BC");
        signature.setParameter(sm2Spec);
        signature.initSign(ecPrivate);
        signature.update(original);
        return signature.sign();
    }


    /**
     * SM2验签
     *
     * @param ecPublic     sm2公钥
     * @param sm2Spec      sm2Spec
     * @param original     原文
     * @param encSignature 签名值
     * @return 验证结果
     * @throws GeneralSecurityException 验签过程失败则抛出异常
     */
    public static boolean verifySM2Signature(PublicKey ecPublic, SM2ParameterSpec sm2Spec, byte[] original, byte[] encSignature) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SM3withSM2", "BC");
        signature.setParameter(sm2Spec);
        signature.initVerify(ecPublic);
        signature.update(original);
        return signature.verify(encSignature);
    }

}
