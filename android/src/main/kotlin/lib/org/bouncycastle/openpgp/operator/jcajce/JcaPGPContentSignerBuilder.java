package lib.org.bouncycastle.openpgp.operator.jcajce;

import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import lib.org.bouncycastle.jcajce.io.OutputStreamFactory;
import lib.org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import lib.org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import lib.org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPPrivateKey;
import lib.org.bouncycastle.openpgp.PGPRuntimeOperationException;
import lib.org.bouncycastle.openpgp.operator.PGPContentSigner;
import lib.org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import lib.org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import lib.org.bouncycastle.util.io.TeeOutputStream;

public class JcaPGPContentSignerBuilder
    implements PGPContentSignerBuilder
{
    private OperatorHelper              helper = new OperatorHelper(new DefaultJcaJceHelper());
    private JcaPGPDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
    private JcaPGPKeyConverter          keyConverter = new JcaPGPKeyConverter();
    private int                         hashAlgorithm;
    private SecureRandom                random;
    private int keyAlgorithm;

    public JcaPGPContentSignerBuilder(int keyAlgorithm, int hashAlgorithm)
    {
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
    }

    public JcaPGPContentSignerBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public JcaPGPContentSignerBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        keyConverter.setProvider(provider);
        digestCalculatorProviderBuilder.setProvider(provider);

        return this;
    }

    public JcaPGPContentSignerBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        keyConverter.setProvider(providerName);
        digestCalculatorProviderBuilder.setProvider(providerName);

        return this;
    }

    public JcaPGPContentSignerBuilder setDigestProvider(Provider provider)
    {
        digestCalculatorProviderBuilder.setProvider(provider);

        return this;
    }

    public JcaPGPContentSignerBuilder setDigestProvider(String providerName)
    {
        digestCalculatorProviderBuilder.setProvider(providerName);

        return this;
    }

    public PGPContentSigner build(final int signatureType, PGPPrivateKey privateKey)
        throws PGPException
    {
        if (privateKey instanceof JcaPGPPrivateKey)
        {
            return build(signatureType, privateKey.getKeyID(), ((JcaPGPPrivateKey)privateKey).getPrivateKey());
        }
        else
        {
            return build(signatureType, privateKey.getKeyID(), keyConverter.getPrivateKey(privateKey));
        }
    }

    public PGPContentSigner build(final int signatureType, final long keyID, final PrivateKey privateKey)
        throws PGPException
    {
        final PGPDigestCalculator digestCalculator = digestCalculatorProviderBuilder.build().get(hashAlgorithm);
        final Signature           signature = helper.createSignature(keyAlgorithm, hashAlgorithm);

        try
        {
            if (random != null)
            {
                signature.initSign(privateKey, random);
            }
            else
            {
                signature.initSign(privateKey);
            }
        }
        catch (InvalidKeyException e)
        {
           throw new PGPException("invalid key.", e);
        }

        return new PGPContentSigner()
        {
            public int getType()
            {
                return signatureType;
            }

            public int getHashAlgorithm()
            {
                return hashAlgorithm;
            }

            public int getKeyAlgorithm()
            {
                return keyAlgorithm;
            }

            public long getKeyID()
            {
                return keyID;
            }

            public OutputStream getOutputStream()
            {
                return new TeeOutputStream(OutputStreamFactory.createStream(signature), digestCalculator.getOutputStream());
            }

            public byte[] getSignature()
            {
                try
                {
                    return signature.sign();
                }
                catch (SignatureException e)
                {
                    throw new PGPRuntimeOperationException("Unable to create signature: " + e.getMessage(), e);
                }
            }

            public byte[] getDigest()
            {
                return digestCalculator.getDigest();
            }
        };
    }
}