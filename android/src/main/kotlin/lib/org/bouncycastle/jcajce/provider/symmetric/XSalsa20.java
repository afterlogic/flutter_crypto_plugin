package lib.org.bouncycastle.jcajce.provider.symmetric;

import lib.org.bouncycastle.crypto.CipherKeyGenerator;
import lib.org.bouncycastle.crypto.engines.XSalsa20Engine;
import lib.org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import lib.org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class XSalsa20
{
    private XSalsa20()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new XSalsa20Engine(), 24);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("XSalsa20", 256, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "XSalsa20 IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = XSalsa20.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.XSALSA20", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.XSALSA20", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.XSALSA20", PREFIX + "$AlgParams");
        }
    }
}
