package lib.org.bouncycastle.pqc.jcajce.provider.rainbow;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import lib.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import lib.org.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import lib.org.bouncycastle.pqc.crypto.rainbow.RainbowPublicKeyParameters;


/**
 * utility class for converting jce/jca Rainbow objects
 * objects into their lib.org.bouncycastle.crypto counterparts.
 */

public class RainbowKeysToParams
{
    static public AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey key)
        throws InvalidKeyException
    {
        if (key instanceof BCRainbowPublicKey)
        {
            BCRainbowPublicKey k = (BCRainbowPublicKey)key;

            return new RainbowPublicKeyParameters(k.getDocLength(), k.getCoeffQuadratic(),
                k.getCoeffSingular(), k.getCoeffScalar());
        }

        throw new InvalidKeyException("can't identify Rainbow public key: " + key.getClass().getName());
    }

    static public AsymmetricKeyParameter generatePrivateKeyParameter(
        PrivateKey key)
        throws InvalidKeyException
    {
        if (key instanceof BCRainbowPrivateKey)
        {
            BCRainbowPrivateKey k = (BCRainbowPrivateKey)key;
            return new RainbowPrivateKeyParameters(k.getInvA1(), k.getB1(),
                k.getInvA2(), k.getB2(), k.getVi(), k.getLayers());
        }

        throw new InvalidKeyException("can't identify Rainbow private key.");
    }
}


