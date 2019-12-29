package com.ainge.easycrypto.certreq;

import com.ainge.easycrypto.exception.CryptoException;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.security.KeyPair;
import java.security.PublicKey;

/**
 * P10,证书请求
 *
 * @author: Ainge
 * @Time: 2019/12/29 14:50
 */
public class JcaPKCS10 {


    /**
     * 创建证书请求
     *
     * @param keyPair    密钥对
     * @param sigAlg     签发算法
     * @param subject    主题信息
     * @param extensions 包含在证书请求的扩展，若无，则传null
     * @return PKCS10CertificationRequest对象
     * @throws OperatorCreationException
     */
    public static PKCS10CertificationRequest createPKCS10(KeyPair keyPair, String sigAlg, X500Name subject, Extensions extensions) throws OperatorCreationException {

        PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
        if (extensions != null) {
            requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
        }
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(keyPair.getPrivate());
        return requestBuilder.build(signer);
    }


    /**
     * 使用公钥检查P10上的签名。
     *
     * @param request 证书请求P10
     * @return 验证结果
     * @throws CryptoException
     */
    public static boolean isValidPKCS10Request(byte[] request) throws CryptoException {
        try {
            JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(request).setProvider("BC");
            PublicKey key = jcaRequest.getPublicKey();
            ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder().setProvider("BC").build(key);
            return jcaRequest.isSignatureValid(verifierProvider);
        } catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }


    }

}
