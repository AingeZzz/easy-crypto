package com.ainge.easycrypto.example;

import com.ainge.easycrypto.cms.signeddata.SignedData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.Test;

import java.security.KeyPair;
import java.util.Map;

/**
 * 本测试都是简单测试，如果需要验证错误的情况。
 * 可以尝试自己按照SignedData的ASN1结构去组装数据进行验证。
 *
 * @author: Ainge
 * @Time: 2020/1/5 14:43
 */
public class SignedDataExample {


    // 不带原文的p7签名例子
    @Test
    public void signedDataDetached() throws Exception {
        // 原文
        byte[] msg = "hello world".getBytes("utf-8");
        // 签发证书
        Map<String, Object> infos = CertSignerExample.signCert(true);
        String alg = (String) infos.get(CertSignerExample._alg);
        X509CertificateHolder certificateHolder = (X509CertificateHolder) infos.get(CertSignerExample._userCert);
        KeyPair keyPair = (KeyPair) infos.get(CertSignerExample._userKeyPair);
        // p7签名不带原文
        CMSSignedData signedData = SignedData.createSignedData(keyPair.getPrivate(), alg, certificateHolder, msg, false);
        // p7验证不带原文的签名
        SignedData.verifySignedDetached(signedData.getEncoded(), msg);
        // 副本签名
        X509CertificateHolder subCert = (X509CertificateHolder) infos.get(CertSignerExample._subCert);
        KeyPair subKeyPair = (KeyPair) infos.get(CertSignerExample._subKeyPair);
        CMSSignedData counterSignature = SignedData.addCounterSignature(signedData, subKeyPair.getPrivate(), alg, subCert);
        // 只验证签名者签名，不验证副本签名
        SignedData.verifySignedDetached(counterSignature.getEncoded(), msg);
        // 验证所有签名，包括副本签名
        SignedData.verifyAllSigners(counterSignature);

    }

    // 带原文的P7签名
    @Test
    public void signedDataEncapsulate() throws Exception {
        // 原文
        byte[] msg = "hello world".getBytes("utf-8");
        // 签发证书
        Map<String, Object> infos = CertSignerExample.signCert(false);
        String alg = (String) infos.get(CertSignerExample._alg);
        X509CertificateHolder certificateHolder = (X509CertificateHolder) infos.get(CertSignerExample._userCert);
        KeyPair keyPair = (KeyPair) infos.get(CertSignerExample._userKeyPair);
        // p7签名不带原文
        CMSSignedData signedData = SignedData.createSignedData(keyPair.getPrivate(), alg, certificateHolder, msg, true);
        // p7验证不带原文的签名
        SignedData.verifySignedEncapsulated(signedData.getEncoded());
        // 副本签名
        X509CertificateHolder subCert = (X509CertificateHolder) infos.get(CertSignerExample._subCert);
        KeyPair subKeyPair = (KeyPair) infos.get(CertSignerExample._subKeyPair);
        CMSSignedData counterSignature = SignedData.addCounterSignature(signedData, subKeyPair.getPrivate(), alg, subCert);
        // 只验证签名者签名，不验证副本签名
        SignedData.verifySignedEncapsulated(counterSignature.getEncoded());
        // 验证所有签名，包括副本签名
        SignedData.verifyAllSigners(counterSignature);

    }


}
