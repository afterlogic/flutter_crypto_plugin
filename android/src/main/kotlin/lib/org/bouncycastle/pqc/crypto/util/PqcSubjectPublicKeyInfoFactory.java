package lib.org.bouncycastle.pqc.crypto.util;

import java.io.IOException;

import lib.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import lib.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import lib.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import lib.org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import lib.org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import lib.org.bouncycastle.pqc.asn1.XMSSKeyParams;
import lib.org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import lib.org.bouncycastle.pqc.asn1.XMSSMTPublicKey;
import lib.org.bouncycastle.pqc.asn1.XMSSPublicKey;
import lib.org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import lib.org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import lib.org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import lib.org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import lib.org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;

/**
 * Factory to create ASN.1 subject public key info objects from lightweight public keys.
 */
public class PqcSubjectPublicKeyInfoFactory
{
    private PqcSubjectPublicKeyInfoFactory()
    {

    }

    /**
     * Create a SubjectPublicKeyInfo public key.
     *
     * @param publicKey the key to be encoded into the info object.
     * @return a SubjectPublicKeyInfo representing the key.
     * @throws IOException on an error encoding the key
     */
    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
        throws IOException
    {
        if (publicKey instanceof QTESLAPublicKeyParameters)
        {
            QTESLAPublicKeyParameters keyParams = (QTESLAPublicKeyParameters)publicKey;
            AlgorithmIdentifier algorithmIdentifier = PqcCryptoUtilUtils.qTeslaLookupAlgID(keyParams.getSecurityCategory());

            return new SubjectPublicKeyInfo(algorithmIdentifier, keyParams.getPublicData());
        }
        else if (publicKey instanceof SPHINCSPublicKeyParameters)
        {
            SPHINCSPublicKeyParameters params = (SPHINCSPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256,
                new SPHINCS256KeyParams(PqcCryptoUtilUtils.sphincs256LookupTreeAlgID(params.getTreeDigest())));
            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getKeyData());
        }
        else if (publicKey instanceof NHPublicKeyParameters)
        {
            NHPublicKeyParameters params = (NHPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);
            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getPubData());
        }
        else if (publicKey instanceof XMSSPublicKeyParameters)
        {
            XMSSPublicKeyParameters keyParams = (XMSSPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss,
                new XMSSKeyParams(keyParams.getParameters().getHeight(), PqcCryptoUtilUtils.xmssLookupTreeAlgID(keyParams.getTreeDigest())));
            return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSPublicKey(keyParams.getPublicSeed(), keyParams.getRoot()));
        }
        else if (publicKey instanceof XMSSMTPublicKeyParameters)
        {
            XMSSMTPublicKeyParameters keyParams = (XMSSMTPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt, new XMSSMTKeyParams(keyParams.getParameters().getHeight(), keyParams.getParameters().getLayers(),
                PqcCryptoUtilUtils.xmssLookupTreeAlgID(keyParams.getTreeDigest())));
            return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSMTPublicKey(keyParams.getPublicSeed(), keyParams.getRoot()));
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }
}
