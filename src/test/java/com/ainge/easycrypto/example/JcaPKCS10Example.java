package com.ainge.easycrypto.example;

import com.ainge.easycrypto.certreq.JcaPKCS10;
import com.ainge.easycrypto.generators.SM2KeypairGenerator;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;

/**
 * @author: Ainge
 * @Time: 2019/12/29 15:45
 */
public class JcaPKCS10Example extends InstallBCSupport {

    @Test
    public void genCertReq() throws Exception {

        KeyPair keyPair = SM2KeypairGenerator.generateSM2KeyPair();
        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "CN")
                .addRDN(BCStyle.ST, "GuangXi")
                .addRDN(BCStyle.L, "Nanning")
                .addRDN(BCStyle.O, "谜之家")
                .addRDN(BCStyle.CN, "AingeZzz").build();

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(
                        new GeneralName(
                                GeneralName.rfc822Name,
                                "aingezhu@163.com")));

        Extensions extensions = extGen.generate();
        PKCS10CertificationRequest certificationRequest = JcaPKCS10.createPKCS10(keyPair, "SM3WithSM2", subject, extensions);
        byte[] encoded = certificationRequest.getEncoded();
        Assert.assertNotNull(encoded);
        Attribute[] attributes = certificationRequest.getAttributes();
        for (Attribute attribute : attributes) {
            if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attribute.getAttrType())) {
                // 来源证书请求的扩展
                ASN1Encodable asn1Encodable = attribute.getAttrValues().getObjectAt(0);
                Extensions instance = Extensions.getInstance(asn1Encodable);
                ASN1ObjectIdentifier[] extensionOIDs = instance.getExtensionOIDs();
                for (ASN1ObjectIdentifier identifier : extensionOIDs) {
                    Extension extension = instance.getExtension(identifier);
                    System.out.println(extension.isCritical());
                    System.out.println(extension.getExtnId());
                    System.out.println(ASN1Dump.dumpAsString(extension.getExtnValue(),true));
                }
            }
        }


    }


}
