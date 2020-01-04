package com.ainge.easycrypto.crl;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
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
    public static X509CRL convertX509CRLHolder(X509CRLHolder crlHolder) throws Exception {
        CertificateFactory cFact = CertificateFactory.getInstance("X.509", "BC");
        return (X509CRL) cFact.generateCRL(new ByteArrayInputStream(crlHolder.getEncoded()));
    }

    public static X509CRLHolder createEmptyCRL(PrivateKey caKey, String sigAlg, X509CertificateHolder caCert, int nextUpdate) throws Exception {
        return signCRL(null, caKey, sigAlg, caCert, nextUpdate, null, CRLReason.lookup(CRLReason.privilegeWithdrawn));
    }

    public static X509CRLHolder updateCRL(PrivateKey caKey, String sigAlg, X509CertificateHolder caCert, X509CRLHolder previousCaCRL, int nextUpdate, X509CertificateHolder certToRevoke, CRLReason crlReason) throws Exception {
        return signCRL(previousCaCRL, caKey, sigAlg, caCert, nextUpdate, certToRevoke, crlReason);
    }

    /**
     * 签发/更新 CRL
     * (CRL一般会分为全量CRL和增量CRL，具体详细请看RFC5280规范)
     *
     * @param previousCaCRL CRL(如果不为空，则代表着更新CRL)
     * @param caKey         签发CRL的私钥
     * @param sigAlg        签发CRL的算法
     * @param caCert        私钥对应的CA证书
     * @param nextUpdate    下次更新该CRL的时间（小时）
     * @param certToRevoke  待吊销的证书
     * @param crlReason     吊销原因
     * @return 一个X509CRLHolder，代表CA的吊销列表。
     */
    public static X509CRLHolder signCRL(X509CRLHolder previousCaCRL, PrivateKey caKey, String sigAlg, X509CertificateHolder caCert, int nextUpdate, X509CertificateHolder certToRevoke, CRLReason crlReason) throws Exception {
        // 指定签发者信息，这次签发时间
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(caCert.getSubject(), calculateDate(0));
        if (previousCaCRL != null) {
            // 如果previousCaCRL不为空，则代表则更新该CRL
            crlGen.addCRL(previousCaCRL);
        }
        // TODO 后续将全量CRL，增量CRL，以及CRL分布策略 加上
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert));
        // 设置CRL Number
        crlGen.addExtension(Extension.cRLNumber, false, getCrlNumber(previousCaCRL));
        // 指定下次更新时间
        crlGen.setNextUpdate(calculateDate(nextUpdate));
        // 添加吊销原因
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(createReasonExtension(CRLReason.privilegeWithdrawn));
        if (certToRevoke != null) {
            // 证书签发者扩展
            Extension certificateIssuerExtension = createCertificateIssuerExtension(certToRevoke.getIssuer());
            extGen.addExtension(certificateIssuerExtension);
            // 注销的证书的序列号要跟crlReason绑定起来
            crlGen.addCRLEntry(certToRevoke.getSerialNumber(), new Date(), extGen.generate());
        }
        // 签发CRL
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(caKey);
        return crlGen.build(signer);
    }


    private static CRLNumber getCrlNumber(X509CRLHolder previousCaCRL) throws IOException {
        if (previousCaCRL != null) {
            Extension extension = previousCaCRL.getExtension(Extension.cRLNumber);
            if (extension != null) {
                // crlNumber是递增的
                ASN1Integer oldCrlNumber = (ASN1Integer) ASN1Integer.fromByteArray(extension.getExtnValue().getOctets());
                BigInteger add = oldCrlNumber.getValue().add(BigInteger.ONE);
                return CRLNumber.getInstance(new ASN1Integer(add));
            }
        }
        return CRLNumber.getInstance(new ASN1Integer(BigInteger.ZERO));
    }

    /**
     * 创建证书签发者扩展（属于CRLEntry的一个关键扩展）
     *
     * @param certificateIssuer 证书的签发者主题
     * @return
     */
    private static Extension createCertificateIssuerExtension(X500Name certificateIssuer) {
        try {
            GeneralNames generalNames = new GeneralNames(new GeneralName(certificateIssuer));
            return new Extension(Extension.certificateIssuer, true, generalNames.getEncoded());
        } catch (IOException ex) {
            throw new IllegalArgumentException("error encoding reason: " + ex.getMessage(), ex);
        }
    }

    /**
     * 创建注销原因扩展（CRLEntry扩展）
     *
     * @param reasonCode 注销原因常量值
     * @return
     * @see CRLReason
     */
    private static Extension createReasonExtension(int reasonCode) {
        CRLReason crlReason = CRLReason.lookup(reasonCode);
        try {
            return new Extension(Extension.reasonCode, false, crlReason.getEncoded());
        } catch (IOException ex) {
            throw new IllegalArgumentException("error encoding reason: " + ex.getMessage(), ex);
        }
    }

    /**
     * 创建失效开始日期扩展（属于CRLEntry扩展）
     * 证书失效开始日前可以比crl签发日期还早
     *
     * @param invalidityDate
     * @return
     */
    private static Extension createInvalidityDateExtension(Date invalidityDate) {
        try {
            ASN1GeneralizedTime asnTime = new ASN1GeneralizedTime(invalidityDate);
            return new Extension(Extension.invalidityDate, false, asnTime.getEncoded());
        } catch (IOException ex) {
            throw new IllegalArgumentException("error encoding reason: " + ex.getMessage(), ex);
        }
    }


}
