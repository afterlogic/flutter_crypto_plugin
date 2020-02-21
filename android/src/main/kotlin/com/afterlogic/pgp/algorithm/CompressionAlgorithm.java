
package com.afterlogic.pgp.algorithm;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;

import java.util.HashMap;
import java.util.Map;

public enum CompressionAlgorithm {

    UNCOMPRESSED(CompressionAlgorithmTags.UNCOMPRESSED),
    ZIP(CompressionAlgorithmTags.ZIP),
    ZLIB(CompressionAlgorithmTags.ZLIB),
    BZIP2(CompressionAlgorithmTags.BZIP2),
    ;

    private static final Map<Integer, CompressionAlgorithm> MAP = new HashMap<>();

    static {
        for (CompressionAlgorithm c : CompressionAlgorithm.values()) {
            MAP.put(c.algorithmId, c);
        }
    }

    public static CompressionAlgorithm fromId(int id) {
        return MAP.get(id);
    }

    private final int algorithmId;

    CompressionAlgorithm(int id) {
        this.algorithmId = id;
    }

    public int getAlgorithmId() {
        return algorithmId;
    }
}
