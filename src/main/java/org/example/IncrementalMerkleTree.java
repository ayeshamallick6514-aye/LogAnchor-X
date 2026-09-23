package org.example;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class IncrementalMerkleTree {

    public static class MerkleProof {
        public String leafHash;
        public String rootHash;
        public List<String> auditPath = new ArrayList<>();
        public List<String> directions = new ArrayList<>();
        public boolean isValid;

        public MerkleProof() {
        }
    }

    private List<String> leaves = new ArrayList<>();
    private String rootHash = "0x0000000000000000000000000000000000000000000000000000000000000000";

    public IncrementalMerkleTree() {
    }

    public IncrementalMerkleTree(List<String> initialLeaves) {
        if (initialLeaves != null) {
            this.leaves = new ArrayList<>(initialLeaves);
            this.rootHash = computeRoot();
        }
    }

    private String computeRoot() {
        if (leaves.isEmpty()) {
            return sha256("EMPTY_TREE");
        }
        List<String> current = new ArrayList<>(leaves);
        while (current.size() > 1) {
            List<String> next = new ArrayList<>();
            for (int i = 0; i < current.size(); i += 2) {
                String left = current.get(i);
                if (i + 1 < current.size()) {
                    next.add(concat(current.get(i), current.get(i + 1)));
                } else {
                    next.add(current.get(i));
                }
            }
            current = next;
        }
        return current.get(0);
    }

    private String concat(String a, String b) {
        return sha256(a + b);
    }

    // Incremental: add a single leaf and update root efficiently
    public void addLeaf(String leafHash) {
        leaves.add(leafHash);
        rootHash = computeRoot();
    }

    public void clear() {
        leaves.clear();
        rootHash = "0x0000000000000000000000000000000000000000000000000000000000000000";
    }

    public String getRootHash() {
        return rootHash;
    }

    public List<String> getLeaves() {
        return new ArrayList<>(leaves);
    }

    public int getLeafCount() {
        return leaves.size();
    }

    public boolean hasLeaf(String leafHash) {
        return leaves.contains(leafHash);
    }

    // Generate proof for a specific leaf hash
    public MerkleProof generateProof(String targetLeaf) {
        MerkleProof proof = new MerkleProof();
        proof.leafHash = targetLeaf;

        if (!leaves.contains(targetLeaf)) {
            proof.isValid = false;
            proof.auditPath = new ArrayList<>();
            proof.directions = new ArrayList<>();
            return proof;
        }

        proof.rootHash = rootHash;

        List<String> current = new ArrayList<>(leaves);
        int idx = leaves.indexOf(targetLeaf);

        while (current.size() > 1) {
            List<String> next = new ArrayList<>();
            for (int i = 0; i < current.size(); i += 2) {
                if (i + 1 < current.size()) {
                    if (i == idx) {
                        proof.auditPath.add(current.get(i + 1));
                        proof.directions.add("R");
                    } else if (i + 1 == idx) {
                        proof.auditPath.add(current.get(i));
                        proof.directions.add("L");
                    }
                    next.add(sha256(concat(current.get(i), current.get(i + 1))));
                } else {
                    next.add(current.get(i));
                }
            }
            idx /= 2;
            current = next;
        }

        proof.isValid = true;
        return proof;
    }

    // Verify a proof
    public boolean verifyProof(MerkleProof proof) {
        if (proof == null || !proof.isValid) return false;
        String curr = proof.leafHash;
        for (int i = 0; i < proof.auditPath.size(); i++) {
            String sibling = proof.auditPath.get(i);
            String dir = proof.directions.get(i);
            if ("L".equals(dir)) {
                curr = sha256(concat(sibling, curr));
            } else {
                curr = sha256(concat(curr, sibling));
            }
        }
        return curr.equals(proof.rootHash);
    }

    static String sha256(String base) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(base.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception ex) {
            return "0000000000000000000000000000000000000000000000000000000000000000";
        }
    }

    static String merkleHash(String left, String right) {
        String combined = left + "|" + right;
        return sha256(combined);
    }
}