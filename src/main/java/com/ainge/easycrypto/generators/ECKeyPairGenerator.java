package com.ainge.easycrypto.generators;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

/**
 * @author: Ainge
 * @Time: 2019/12/21 17:57
 */
public class ECKeyPairGenerator {


    /**
     * Generate a EC key pair on the passed in named curve.
     *
     * @param curveName the name of the curve to generate the key pair on.
     * @return a EC KeyPair
     */
    public static KeyPair generateECKeyPair(String curveName)
            throws GeneralSecurityException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("EC", "BC");

        keyPair.initialize(new ECGenParameterSpec(curveName));

        return keyPair.generateKeyPair();
    }

    /**
     * Generate a EC key pair on the P-256 curve.
     *
     * @return a EC KeyPair
     */
    public static KeyPair generateECKeyPair()
            throws GeneralSecurityException {
        return generateECKeyPair("P-256");
    }


}
