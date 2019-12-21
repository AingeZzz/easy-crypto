package com.ainge.easycrypto.digest;

import org.bouncycastle.util.Arrays;

import java.security.MessageDigest;
import java.util.Collections;
import java.util.List;

/**
 * AuditPath carrier created by the MerkleTree class to provide proof of presence for
 * a value in the tree.
 */
public class AuditPath {
    /**
     * A carrier for a node hash, the combine() method ensures the hash
     * is added correctly to the hash it is been combined with on evaluation.
     */
    public static class Element {
        byte[] value;
        boolean isLeft;

        Element(boolean isLeft, byte[] value) {
            this.isLeft = isLeft;
            this.value = value;
        }

        /**
         * Return this element's hash combined with the passed in hash
         * in a format suitable for passing into a digest function.
         *
         * @param hash the hash to be combined with this element.
         * @return a concatenation of the element hash and the passed in hash.
         */
        public byte[] combine(byte[] hash) {
            if (isLeft) {
                return Arrays.concatenate(new byte[]{1}, value, hash);
            } else {
                return Arrays.concatenate(new byte[]{1}, hash, value);
            }
        }
    }

    private final byte[] rootHash;
    private final List<Element> elements;

    AuditPath(byte[] rootHash, List<Element> elements) {
        this.rootHash = rootHash;
        this.elements = Collections.unmodifiableList(elements);
    }

    /**
     * Return the root hash for the tree this audit path is from.
     *
     * @return the root hash for the tree.
     */
    public byte[] getRootHash() {
        return Arrays.clone(rootHash);
    }

    /**
     * Return the list representing the elements of the
     * audit path leading to the root of the tree.
     *
     * @return a list of hash elements.
     */
    public List<Element> getElements() {
        return elements;
    }

    /**
     * Return true if the passed in data value is the one matched
     * by the audit path.
     *
     * @param digest the digest to use for hash calculations
     * @param data   the value that is being checked for.
     * @return true if the audit path is for the data, false otherwise.
     */
    public boolean isMatched(MessageDigest digest, byte[] data) {
        digest.update((byte) 0x00);
        digest.update(data, 0, data.length);

        byte[] dig = digest.digest();

        for (AuditPath.Element element : elements) {
            dig = digest.digest(element.combine(dig));
        }

        return Arrays.constantTimeAreEqual(getRootHash(), dig);
    }
}
