package lib.org.bouncycastle.jcajce.provider.asymmetric.gost;

import java.math.BigInteger;

import lib.org.bouncycastle.crypto.params.GOST3410Parameters;
import lib.org.bouncycastle.util.Arrays;
import lib.org.bouncycastle.util.Fingerprint;
import lib.org.bouncycastle.util.Strings;

class GOSTUtil
{
    static String privateKeyToString(String algorithm, BigInteger x, GOST3410Parameters gostParams)
    {
        StringBuffer buf = new StringBuffer();
        String        nl = Strings.lineSeparator();

        BigInteger y = gostParams.getA().modPow(x, gostParams.getP());

        buf.append(algorithm);
        buf.append(" Private Key [").append(generateKeyFingerprint(y, gostParams)).append("]").append(nl);
        buf.append("                  Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    static String publicKeyToString(String algorithm, BigInteger y, GOST3410Parameters gostParams)
    {
        StringBuffer buf = new StringBuffer();
        String nl = Strings.lineSeparator();

        buf.append(algorithm);
        buf.append(" Public Key [").append(generateKeyFingerprint(y, gostParams)).append("]").append(nl);
        buf.append("                 Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    private static String generateKeyFingerprint(BigInteger y, GOST3410Parameters dhParams)
    {
            return new Fingerprint(
                Arrays.concatenate(
                    y.toByteArray(),
                    dhParams.getP().toByteArray(), dhParams.getA().toByteArray())).toString();
    }
}
