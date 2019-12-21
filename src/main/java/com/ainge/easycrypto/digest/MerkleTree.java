package com.ainge.easycrypto.digest;

import org.bouncycastle.util.Arrays;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * 基于AVL +树（其中数据始终存储在叶节点中）的Merkle树的实现
 */
public class MerkleTree {

    /**
     * 消息摘要算法
     */
    private final MessageDigest digest;
    /**
     * 使用消息摘要算法计算出的空Hash值
     */
    private final byte[] emptyHash;

    /**
     * 根节点
     */
    Node root;

    /**
     * Base Constructor
     *
     * @param digest the digest to generate the tree's hashes with.
     */
    public MerkleTree(MessageDigest digest) {
        this.digest = digest;
        this.emptyHash = digest.digest();
    }

    /**
     * Insert value into the Merkle tree.
     *
     * @param value the value to be inserted.
     */
    public void insert(byte[] value) {
        LeafNode leafNode = createLeafNode(Arrays.clone(value));

        if (root == null) {
            root = leafNode;
        } else {
            root = insertLeaf(root, leafNode);
        }
    }

    /**
     * Return an AuditPath leading to value if it is in the tree. Null otherwise.
     *
     * @param value the value we want the audit path for.
     * @return an AuditPath, or null if value is not present.
     */
    public AuditPath generateAuditPath(byte[] value) {
        LeafNode leafNode = createLeafNode(Arrays.clone(value));

        if (root == null) {
            return null;
        }
        List pathElements = new ArrayList();

        boolean found = buildAuditPath(pathElements, root, leafNode);

        if (found) {
            return new AuditPath(root.hash, pathElements);
        }

        return null;
    }

    private LeafNode createLeafNode(byte[] nodeValue) {
        // the zero prefix is to make sure we use a different calculation
        // from a branch node. See section 2.1 of RFC 6962 for further details.
        return new LeafNode(hash((byte) 0x00, nodeValue), nodeValue);
    }

    private boolean buildAuditPath(
            List<AuditPath.Element> proof, Node treeNode, LeafNode newNode) {
        if (newNode.isGreaterThan(treeNode)) {
            if (treeNode instanceof BranchNode) {
                BranchNode branch = (BranchNode) treeNode;

                boolean found = buildAuditPath(proof, branch.right, newNode);

                if (found) {
                    proof.add(new AuditPath.Element(true, getHash(branch.left)));
                }
                return found;
            } else {
                return false;
            }
        } else {
            if (treeNode instanceof BranchNode) {
                BranchNode branch = (BranchNode) treeNode;

                boolean found = buildAuditPath(proof, branch.left, newNode);

                if (found) {
                    proof.add(new AuditPath.Element(false, getHash(branch.right)));
                }

                return found;
            } else {
                return Arrays.constantTimeAreEqual(treeNode.hash, newNode.hash);
            }
        }
    }

    private byte[] getHash(Node node) {
        if (node == null) {
            return emptyHash;
        } else {
            return node.hash;
        }
    }

    // the 01 prefix is to make sure we use a different calculation
    // from a leaf node. See section 2.1 of RFC 6962 for further details.
    private byte[] calculateBranchHash(Node left, Node right) {
        byte[] leftHash = (left != null) ? left.hash : emptyHash;
        byte[] rightHash = (right != null) ? right.hash : emptyHash;

        return hash((byte) 0x01, Arrays.concatenate(leftHash, rightHash));
    }

    private byte[] hash(byte preFix, byte[] value) {
        digest.update(preFix);
        digest.update(value);

        return digest.digest();
    }

    // balancing action - left rotate
    private BranchNode rotateLeft(BranchNode n) {
        n.left = new BranchNode(n.left, ((BranchNode) n.right).left);
        n.right = ((BranchNode) n.right).right;

        balance((BranchNode) n.left);

        n.recalculateKeyValue();
        n.recalculateHash();

        return n;
    }

    // balancing action - right rotate
    private BranchNode rotateRight(BranchNode n) {
        n.right = new BranchNode(((BranchNode) n.left).right, n.right);
        n.left = ((BranchNode) n.left).left;

        balance((BranchNode) n.right);

        n.recalculateKeyValue();
        n.recalculateHash();

        return n;
    }

    private Node insertLeaf(Node treeNode, LeafNode newNode) {
        if (treeNode == null) {
            return newNode;
        } else if (treeNode.isGreaterThan(newNode)) {
            if (treeNode instanceof BranchNode) {
                BranchNode branch = (BranchNode) treeNode;

                branch.left = insertLeaf(branch.left, newNode);

                branch.recalculateKeyValue();
                branch.recalculateHash();

                return balance(branch);
            } else {
                return new BranchNode(newNode, treeNode);
            }
        } else {
            if (treeNode instanceof BranchNode) {
                BranchNode branch = (BranchNode) treeNode;

                branch.right = insertLeaf(branch.right, newNode);

                branch.recalculateKeyValue();
                branch.recalculateHash();

                return balance(branch);
            } else {
                return new BranchNode(treeNode, newNode);
            }
        }
    }

    // check BranchNode to see if it's as balanced as we can make it.
    private BranchNode balance(BranchNode node) {
        int balance = node.getBalance();

        // left side is higher
        if (balance == 1) {
            return rotateRight(node);
        }

        // right side is higher
        if (balance == -1) {
            return rotateLeft(node);
        }

        // left right probably required
        if (balance >= 2) {
            if (((BranchNode) node.left).right instanceof LeafNode) {
                node.left = rotateRight((BranchNode) node.left);

                return node;
            } else {
                node.left = rotateLeft((BranchNode) node.left);

                return rotateRight(node);
            }
        }

        // right left probably required
        if (balance <= -2) {
            if (((BranchNode) node.right).left instanceof LeafNode) {
                node.right = rotateLeft((BranchNode) node.right);

                return node;
            } else {
                node.right = rotateRight((BranchNode) node.right);

                return rotateLeft(node);
            }
        }

        return node;
    }

    /**
     * Return a dump of the tree - inorder traversal.
     *
     * @return a String dump of the tree.
     */
    public String toString() {
        StringBuilder sBld = new StringBuilder();

        toString(sBld, root);

        return sBld.toString();
    }

    private void toString(StringBuilder sBld, Node root) {
        if (root instanceof BranchNode) {
            sBld.append("(N[");
            sBld.append(new BigInteger(1, root.keyValue).toString(16));
            sBld.append("]: ");
            toString(sBld, ((BranchNode) root).left);
            sBld.append(", ");
            toString(sBld, ((BranchNode) root).right);
        } else {
            sBld.append("(L[");
            sBld.append(new BigInteger(1, root.keyValue).toString(16));
            sBld.append("]: ");
            sBld.append(new BigInteger(1, ((LeafNode) root).nodeValue).toString());
        }
        sBld.append(")");
    }


    // base class for a tree node.
    private class Node {
        byte[] keyValue;
        byte[] hash;

        // Return true if the keyValue in this node is
        // greater than the keyValue in other.
        boolean isGreaterThan(Node other) {
            for (int i = 0; i != keyValue.length; i++) {
                int thisB = this.keyValue[i] & 0xff;
                int otherB = other.keyValue[i] & 0xff;
                if (thisB > otherB) {
                    return true;
                } else if (thisB < otherB) {
                    return false;
                }
            }
            return false;
        }
    }

    // the leaf node.
    private class LeafNode
            extends Node {
        final byte[] nodeValue;

        LeafNode(byte[] nodeHash, byte[] nodeValue) {
            this.keyValue = nodeHash;
            this.nodeValue = nodeValue;
            this.hash = nodeHash;
        }
    }

    // the branch node.
    private class BranchNode
            extends Node {
        Node left, right;

        BranchNode(Node left, Node right) {
            this.left = left;
            this.right = right;
            this.recalculateHash();
            this.recalculateKeyValue();
        }

        void recalculateKeyValue() {
            this.keyValue = findMaxValue(left);
        }

        void recalculateHash() {
            this.hash = calculateBranchHash(left, right);
        }

        int getBalance() {
            return getHeight(this.left) - getHeight(this.right);
        }

        private int getHeight(Node root) {
            if (root instanceof BranchNode) {
                return 1 + Math.max(getHeight(((BranchNode) root).left), getHeight(((BranchNode) root).right));
            }

            return 0;
        }

        private byte[] findMaxValue(Node root) {
            if (root instanceof BranchNode) {
                return findMaxValue(((BranchNode) root).right);
            } else {
                return ((LeafNode) root).keyValue;
            }
        }
    }

}
