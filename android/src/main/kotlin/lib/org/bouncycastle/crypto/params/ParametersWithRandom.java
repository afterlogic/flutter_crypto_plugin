package lib.org.bouncycastle.crypto.params;

import java.security.SecureRandom;

import lib.org.bouncycastle.crypto.CipherParameters;
import lib.org.bouncycastle.crypto.CryptoServicesRegistrar;

public class ParametersWithRandom
    implements CipherParameters
{
    private SecureRandom        random;
    private CipherParameters    parameters;

    public ParametersWithRandom(
        CipherParameters    parameters,
        SecureRandom        random)
    {
        this.random = random;
        this.parameters = parameters;
    }

    public ParametersWithRandom(
        CipherParameters    parameters)
    {
        this(parameters, CryptoServicesRegistrar.getSecureRandom());
    }

    public SecureRandom getRandom()
    {
        return random;
    }

    public CipherParameters getParameters()
    {
        return parameters;
    }
}