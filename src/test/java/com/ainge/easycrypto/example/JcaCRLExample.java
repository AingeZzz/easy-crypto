package com.ainge.easycrypto.example;

import com.ainge.easycrypto.crl.JcaX509CRL;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

/**
 * @author: Ainge
 * @Time: 2020/1/4 12:22
 */
public class JcaCRLExample extends InstallBCSupport{



    @Test
    public void signCRL() throws Exception {
        // 签发证书
        Map<String, Object> stringObjectMap = CertSignerExample.signCert();
        KeyPair subKeyPair = (KeyPair)stringObjectMap.get(CertSignerExample._subKeyPair);
        X509CertificateHolder x509Certificate = (X509CertificateHolder) stringObjectMap.get(CertSignerExample._subCert);
        X509CertificateHolder userCert = (X509CertificateHolder) stringObjectMap.get(CertSignerExample._userCert);
        X500Name issuer = userCert.getIssuer();
        System.out.println(issuer);

        int nextUpdate = 24 * 7;
        // 签发CRL,理由证书挂起
        X509CRLHolder crl = JcaX509CRL.signCRL(null, subKeyPair.getPrivate(), "SHA256WithRSA", x509Certificate, nextUpdate,userCert, CRLReason.lookup(CRLReason.certificateHold));
        X509CRL x509CRL = JcaX509CRL.convertX509CRLHolder(crl);
        System.out.println(x509CRL);
        X509CRLEntry revokedCertificate = x509CRL.getRevokedCertificate(userCert.getSerialNumber());
        Assert.assertNotNull(revokedCertificate);

        // CRL下次更新时间到了，将证书解挂
        X509CRLHolder nexCrl = JcaX509CRL.updateCRL(subKeyPair.getPrivate(), "SHA256WithRSA", x509Certificate, crl, nextUpdate, userCert, CRLReason.lookup(CRLReason.removeFromCRL));
        X509CRL nextX509CRL = JcaX509CRL.convertX509CRLHolder(nexCrl);
        System.out.println(nextX509CRL);
    }


}
