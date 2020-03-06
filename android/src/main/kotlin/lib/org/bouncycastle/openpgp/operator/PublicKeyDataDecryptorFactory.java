package lib.org.bouncycastle.openpgp.operator;

import lib.org.bouncycastle.openpgp.PGPException;

public interface PublicKeyDataDecryptorFactory
    extends PGPDataDecryptorFactory
{
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
            throws PGPException;
}
