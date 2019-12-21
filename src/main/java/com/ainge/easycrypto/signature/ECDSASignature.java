package com.ainge.easycrypto.signature;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * @author: Ainge
 * @Time: 2019/12/21 18:40
 */
public class ECDSASignature {

    private static final String ALGORITHM = "SHA256withECDSA";

    /**
     * 签名
     *
     * @param ecPrivate ecPrivateKey
     * @param original  原文（待签名数据）
     * @return 签名数据
     * @throws GeneralSecurityException 签名过程失败抛出异常
     */
    public static byte[] generateECDSASignature(PrivateKey ecPrivate, byte[] original) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(ALGORITHM, "BC");
        signature.initSign(ecPrivate);
        signature.update(original);
        return signature.sign();
    }

    /**
     * 验签
     *
     * @param ecPublic     ecPublicKey
     * @param original     原文
     * @param encSignature 签名数据
     * @return 验签结果
     * @throws GeneralSecurityException 验证过程失败会抛出异常
     */
    public static boolean verifyECDSASignature(PublicKey ecPublic, byte[] original, byte[] encSignature) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(ALGORITHM, "BC");
        signature.initVerify(ecPublic);
        signature.update(original);
        return signature.verify(encSignature);
    }


}
