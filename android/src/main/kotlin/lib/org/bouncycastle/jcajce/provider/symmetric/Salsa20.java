package lib.org.bouncycastle.jcajce.provider.symmetric;

import lib.org.bouncycastle.crypto.CipherKeyGenerator;
import lib.org.bouncycastle.crypto.engines.Salsa20Engine;
import lib.org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import lib.org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class Salsa20
{
    private Salsa20()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new Salsa20Engine(), 8);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("Salsa20", 128, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Salsa20 IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = Salsa20.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.SALSA20", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.SALSA20", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.SALSA20", PREFIX + "$AlgParams");
        }
    }
}
