package lib.org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

import lib.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import lib.org.bouncycastle.asn1.x9.X962Parameters;
import lib.org.bouncycastle.asn1.x9.X9ECParameters;
import lib.org.bouncycastle.asn1.x9.X9ECPoint;
import lib.org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import lib.org.bouncycastle.bcpg.MPInteger;
import lib.org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import lib.org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import lib.org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import lib.org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import lib.org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import lib.org.bouncycastle.math.ec.ECPoint;
import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPPublicKey;
import lib.org.bouncycastle.openpgp.PGPUtil;
import lib.org.bouncycastle.openpgp.operator.PGPPad;
import lib.org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import lib.org.bouncycastle.openpgp.operator.RFC6637Utils;

public class JcePublicKeyKeyEncryptionMethodGenerator
    extends PublicKeyKeyEncryptionMethodGenerator
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private SecureRandom random;
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();

    /**
     * Create a public key encryption method generator with the method to be based on the passed in key.
     *
     * @param key   the public key to use for encryption.
     */
    public JcePublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key)
    {
        super(key);
    }

    public JcePublicKeyKeyEncryptionMethodGenerator setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        keyConverter.setProvider(provider);

        return this;
    }

    public JcePublicKeyKeyEncryptionMethodGenerator setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        keyConverter.setProvider(providerName);

        return this;
    }

    /**
     * Provide a user defined source of randomness.
     *
     * @param random  the secure random to be used.
     * @return  the current generator.
     */
    public JcePublicKeyKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    protected byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo)
        throws PGPException
    {
        try
        {
            if (pubKey.getAlgorithm() == PublicKeyAlgorithmTags.ECDH)
            {
                // Generate the ephemeral key pair
                ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)pubKey.getPublicKeyPacket().getKey();
                X9ECParameters x9Params = JcaJcePGPUtil.getX9Parameters(ecKey.getCurveOID());
                AlgorithmParameters ecAlgParams = helper.createAlgorithmParameters("EC");

                ecAlgParams.init(new X962Parameters(ecKey.getCurveOID()).getEncoded());

                KeyPairGenerator kpGen = helper.createKeyPairGenerator("EC");

                kpGen.initialize(ecAlgParams.getParameterSpec(AlgorithmParameterSpec.class));

                KeyPair ephKP = kpGen.generateKeyPair();

                KeyAgreement agreement = helper.createKeyAgreement(RFC6637Utils.getAgreementAlgorithm(pubKey.getPublicKeyPacket()));

                agreement.init(ephKP.getPrivate(), new UserKeyingMaterialSpec(RFC6637Utils.createUserKeyingMaterial(pubKey.getPublicKeyPacket(), new JcaKeyFingerprintCalculator())));

                agreement.doPhase(keyConverter.getPublicKey(pubKey), true);

                Key key = agreement.generateSecret(RFC6637Utils.getKeyEncryptionOID(ecKey.getSymmetricKeyAlgorithm()).getId());

                Cipher c = helper.createKeyWrapper(ecKey.getSymmetricKeyAlgorithm());

                c.init(Cipher.WRAP_MODE, key, random);

                byte[] paddedSessionData = PGPPad.padSessionData(sessionInfo);

                byte[] C = c.wrap(new SecretKeySpec(paddedSessionData, PGPUtil.getSymmetricCipherName(sessionInfo[0])));

                SubjectPublicKeyInfo epPubKey = SubjectPublicKeyInfo.getInstance(ephKP.getPublic().getEncoded());

                X9ECPoint derQ = new X9ECPoint(x9Params.getCurve(), epPubKey.getPublicKeyData().getBytes());

                ECPoint publicPoint = derQ.getPoint();

                byte[] VB = new MPInteger(new BigInteger(1, publicPoint.getEncoded(false))).getEncoded();

                byte[] rv = new byte[VB.length + 1 + C.length];

                System.arraycopy(VB, 0, rv, 0, VB.length);
                rv[VB.length] = (byte)C.length;
                System.arraycopy(C, 0, rv, VB.length + 1, C.length);

                return rv;
            }
            else
            {
                Cipher c = helper.createPublicKeyCipher(pubKey.getAlgorithm());

                Key key = keyConverter.getPublicKey(pubKey);

                c.init(Cipher.ENCRYPT_MODE, key, random);

                return c.doFinal(sessionInfo);
            }
        }
        catch (IllegalBlockSizeException e)
        {
            throw new PGPException("illegal block size: " + e.getMessage(), e);
        }
        catch (BadPaddingException e)
        {
            throw new PGPException("bad padding: " + e.getMessage(), e);
        }
        catch (InvalidKeyException e)
        {
            throw new PGPException("key invalid: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new PGPException("unable to encode MPI: " + e.getMessage(), e);
        }
        catch (GeneralSecurityException e)
        {
            throw new PGPException("unable to set up ephemeral keys: " + e.getMessage(), e);
        }
    }
}