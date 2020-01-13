package com.ainge.easycrypto.example;

import com.ainge.easycrypto.generators.PGPKeyPairGenerator;
import com.ainge.easycrypto.generators.RSAKeyPairGenerator;
import com.ainge.easycrypto.pgp.PGPKeyHolder;
import com.ainge.easycrypto.pgp.PGPUtils;
import com.ainge.easycrypto.pgp.PersonalKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.junit.Test;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.Optional;

/**
 * @author: Ainge
 * @Time: 2020/1/12 22:14
 */
public class PGPKeyPairGenExample extends InstallBCSupport{


    @Test
    public void keyPairGenTest() throws Exception {

        String identity = "Ainge (for_email) <zaj9404@163.com>";
        KeyPair masterKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        KeyPair subKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048);
        char[] passphrase = "123456".toCharArray();
        byte[][] bytes = PGPKeyPairGenerator.generateKeyRing(identity,passphrase , masterKeyPair, subKeyPair);
        System.out.println(Arrays.toString(bytes[0]));
        System.out.println(Arrays.toString(bytes[1]));
        Optional<PGPKeyHolder> pgpCoderKey = PGPUtils.readPublicKey(bytes[1]);
        PGPKeyHolder pub = pgpCoderKey.get();
        PersonalKey personalKey = PersonalKey.load(bytes[0], passphrase);
        System.out.println(personalKey.getBridgeCertificate());

    }


}
