package lib.org.bouncycastle.jcajce.provider.util;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import lib.org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import lib.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

public interface AsymmetricKeyInfoConverter
{
    PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException;

    PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException;
}
