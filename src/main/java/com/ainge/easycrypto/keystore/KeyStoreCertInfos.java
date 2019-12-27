package com.ainge.easycrypto.keystore;

import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * @author: Ainge
 * @Time: 2019/12/26 23:22
 */
public class KeyStoreCertInfos {
    private Certificate certificate;
    private PrivateKey privateKey;

    public KeyStoreCertInfos() {
    }

    public KeyStoreCertInfos(Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public KeyStoreCertInfos(Certificate certificate, Key privateKey) {
        this.certificate = certificate;
        this.setPrivateKey(privateKey);
    }

    public Certificate getCertificate() {
        return certificate;
    }


    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }


    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public void setPrivateKey(Key privateKey) {
        if (privateKey instanceof PrivateKey) {
            this.privateKey = (PrivateKey) privateKey;
        }
        // ignore
    }
}
