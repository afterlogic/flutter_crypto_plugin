package lib.org.bouncycastle.jcajce.provider.symmetric;

import lib.org.bouncycastle.crypto.CipherKeyGenerator;
import lib.org.bouncycastle.crypto.engines.ChaCha7539Engine;
import lib.org.bouncycastle.crypto.engines.ChaChaEngine;
import lib.org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import lib.org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class ChaCha
{
    private ChaCha()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new ChaChaEngine(), 8);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("ChaCha", 128, new CipherKeyGenerator());
        }
    }

    public static class Base7539
        extends BaseStreamCipher
    {
        public Base7539()
        {
            super(new ChaCha7539Engine(), 12);
        }
    }

    public static class KeyGen7539
        extends BaseKeyGenerator
    {
        public KeyGen7539()
        {
            super("ChaCha7539", 256, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "ChaCha7539 IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = ChaCha.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.CHACHA", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.CHACHA", PREFIX + "$KeyGen");

            provider.addAlgorithm("Cipher.CHACHA7539", PREFIX + "$Base7539");
            provider.addAlgorithm("KeyGenerator.CHACHA7539", PREFIX + "$KeyGen7539");
            provider.addAlgorithm("AlgorithmParameters.CHACHA7539", PREFIX + "$AlgParams");
            provider.addAlgorithm("Alg.Alias.Cipher.CHACHA20", "CHACHA7539");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.CHACHA20", "CHACHA7539");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.CHACHA20", "CHACHA7539");
        }
    }
}
