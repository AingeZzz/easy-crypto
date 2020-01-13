package com.ainge.easycrypto.pgp;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;

/**
 * A custom X.509 extension for a PGP public key.
 *
 * @author: Ainge
 * @Time: 2020/1/14 00:35
 */
public class SubjectPGPPublicKeyInfo extends ASN1Object {
    /**
     * 自定义扩展OID
     */
    public static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("2.25.12345678909876543210123456789098765432");
    private final DERBitString keyData;

    SubjectPGPPublicKeyInfo(byte[] publicKey) {
        keyData = new DERBitString(publicKey);
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return keyData;
    }
}
