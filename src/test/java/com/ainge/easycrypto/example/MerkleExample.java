package com.ainge.easycrypto.example;

import com.ainge.easycrypto.digest.AuditPath;
import com.ainge.easycrypto.digest.MerkleTree;
import org.bouncycastle.util.BigIntegers;
import org.junit.Test;

import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * @author: Ainge
 * @Time: 2019/12/21 17:28
 */
public class MerkleExample {

    @Test
    public void merkleExampleTest() throws Exception {
        // 消息摘要算法
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        // 构造MerkleTree
        MerkleTree tree = new MerkleTree(sha256);
        // populate the tree with data.
        for (int i = 0; i != 1000; i += 2) {
            tree.insert(BigIntegers.asUnsignedByteArray(BigInteger.valueOf(i)));
        }
        for (int i = 1001; i > 0; i -= 2) {
            tree.insert(BigIntegers.asUnsignedByteArray(BigInteger.valueOf(i)));
        }
        // generate an audit path for a value of interest.
        byte[] value = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(239));

        AuditPath path = tree.generateAuditPath(value);
        System.out.println(tree.toString());

        System.out.println("Value on path: " + path.isMatched(sha256, value));

        // try using the path to match a different value.
        value = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(100));

        System.out.println("Value on path: " + path.isMatched(sha256, value));
    }


}
