package lib.org.bouncycastle.jcajce.provider.config;

import java.security.spec.DSAParameterSpec;
import java.util.Map;
import java.util.Set;

import javax.crypto.spec.DHParameterSpec;

import lib.org.bouncycastle.jce.spec.ECParameterSpec;

public interface ProviderConfiguration
{
    ECParameterSpec getEcImplicitlyCa();

    DHParameterSpec getDHDefaultParameters(int keySize);

    DSAParameterSpec getDSADefaultParameters(int keySize);

    Set getAcceptableNamedCurves();

    Map getAdditionalECParameters();
}
