package com.ainge.easycrypto.crl;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Date;

/**
 * 证书注销列表
 *
 * @author: Ainge
 * @Time: 2020/1/3 22:58
 */
public class JcaX509CRL {


    /**
     * 以秒为单位计算日期（满足 RFC 5280规范要求）
     *
     * @param hoursInFuture 几个小时，可以为负
     * @return 日前设置为：now + (hoursInFuture * 60 * 60) seconds
     */
    public static Date calculateDate(int hoursInFuture) {
        long secs = System.currentTimeMillis() / 1000;
        return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
    }

    /**
     * 一个简单方法用于将X509CRLHolder转为X509CRL对象
     */
    public static X509CRL convertX509CRLHolder(X509CertificateHolder crlHolder) throws Exception {
        CertificateFactory cFact = CertificateFactory.getInstance("X.509", "BC");
        return (X509CRL) cFact.generateCRL(new ByteArrayInputStream(crlHolder.getEncoded()));
    }

    public static X509CRLHolder createEmptyCRL(PrivateKey caKey, String sigAlg, X509CertificateHolder caCert) throws Exception {
        return signCRL(null, caKey, sigAlg, caCert, null, CRLReason.lookup(CRLReason.privilegeWithdrawn));
    }

    public static X509CRLHolder updateCRL(PrivateKey caKey, String sigAlg, X509CertificateHolder caCert, X509CRLHolder previousCaCRL, X509CertificateHolder certToRevoke, CRLReason crlReason) throws Exception {
        return signCRL(previousCaCRL, caKey, sigAlg, caCert, certToRevoke, crlReason);
    }

    /**
     * 签发/更新 CRL
     * (CRL一般会分为全量CRL和增量CRL，具体详细请看RFC5280规范)
     *
     * @param previousCaCRL CRL(如果不为空，则代表着更新CRL)
     * @param caKey         签发CRL的私钥
     * @param sigAlg        签发CRL的算法
     * @param caCert        私钥对应的CA证书
     * @param certToRevoke  待吊销的证书
     * @param crlReason     吊销原因
     * @return 一个X509CRLHolder，代表CA的吊销列表。
     */
    public static X509CRLHolder signCRL(X509CRLHolder previousCaCRL, PrivateKey caKey, String sigAlg, X509CertificateHolder caCert, X509CertificateHolder certToRevoke, CRLReason crlReason) throws Exception {
        // 指定签发者信息，这次签发时间
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(caCert.getSubject(), calculateDate(0));
        if (previousCaCRL != null) {
            // 如果previousCaCRL不为空，则代表则更新该CRL
            crlGen.addCRL(previousCaCRL);
        }
        // 指定下次更新时间
        crlGen.setNextUpdate(calculateDate(24 * 7));
        // 添加吊销原因
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.reasonCode, false, crlReason);
        if (certToRevoke != null) {
            // 注销的证书的序列号要跟crlReason绑定起来
            crlGen.addCRLEntry(certToRevoke.getSerialNumber(), new Date(), extGen.generate());
        }
        // 签发CRL
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert));
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(caKey);
        return crlGen.build(signer);
    }


}
