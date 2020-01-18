package com.ainge.easycrypto.pgp;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;

/**
 * PGP 签名/验签
 *
 * @author: Ainge
 * @Time: 2020/1/18 18:55
 */
public class PGPSignature {

    public static byte[] createSignedObject(int signingAlg, PGPPrivateKey signingKey, byte[] data) throws PGPException, IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream bcOut = new BCPGOutputStream(bOut);
        PGPSignatureGenerator sGen =
                new PGPSignatureGenerator(
                        new JcaPGPContentSignerBuilder(signingAlg, PGPUtil.SHA384)
                                .setProvider("BC"));
        sGen.init(org.bouncycastle.openpgp.PGPSignature.BINARY_DOCUMENT, signingKey);
        sGen.generateOnePassVersion(false).encode(bcOut);
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();

        OutputStream lOut = lGen.open(bcOut,
                PGPLiteralData.BINARY, "_CONSOLE", data.length, new Date());
        for (int i = 0; i != data.length; i++) {
            lOut.write(data[i]);
            sGen.update(data[i]);
        }
        lGen.close();
        sGen.generate().encode(bcOut);
        return bOut.toByteArray();
    }

    public static boolean verifySignedObject(PGPPublicKey verifyingKey, byte[] pgpSignedData)
            throws PGPException, IOException {
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpSignedData);
        PGPOnePassSignatureList onePassList = (PGPOnePassSignatureList) pgpFact.nextObject();
        PGPOnePassSignature ops = onePassList.get(0);
        PGPLiteralData literalData = (PGPLiteralData) pgpFact.nextObject();
        InputStream dIn = literalData.getInputStream();
        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), verifyingKey);
        int ch;
        while ((ch = dIn.read()) >= 0) {
            ops.update((byte) ch);
        }
        PGPSignatureList sigList = (PGPSignatureList) pgpFact.nextObject();
        org.bouncycastle.openpgp.PGPSignature sig = sigList.get(0);
        return ops.verify(sig);
    }

}
