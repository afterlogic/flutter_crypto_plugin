
package com.afterlogic.pgp.key.selection.key;



import com.afterlogic.pgp.util.MultiMap;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


public abstract class PublicKeySelectionStrategy<O> implements KeySelectionStrategy<PGPPublicKey, PGPPublicKeyRing, O> {

    @Override
    public Set<PGPPublicKey> selectKeysFromKeyRing(O identifier,  PGPPublicKeyRing ring) {
        Set<PGPPublicKey> keys = new HashSet<>();
        for (Iterator<PGPPublicKey> i = ring.getPublicKeys(); i.hasNext(); ) {
            PGPPublicKey key = i.next();
            if (accept(identifier, key)) keys.add(key);
        }
        return keys;
    }

    @Override
    public MultiMap<O, PGPPublicKey> selectKeysFromKeyRings(MultiMap<O, PGPPublicKeyRing> keyRings) {
        MultiMap<O, PGPPublicKey> keys = new MultiMap<>();
        for (O identifier : keyRings.keySet()) {
            for (PGPPublicKeyRing ring : keyRings.get(identifier)) {
                keys.put(identifier, selectKeysFromKeyRing(identifier, ring));
            }
        }
        return keys;
    }
}
