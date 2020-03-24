package lib.org.bouncycastle.asn1.eac;

import lib.org.bouncycastle.asn1.ASN1Object;
import lib.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import lib.org.bouncycastle.asn1.ASN1Sequence;

public abstract class PublicKeyDataObject
    extends ASN1Object
{
    public static PublicKeyDataObject getInstance(Object obj)
    {
        if (obj instanceof PublicKeyDataObject)
        {
            return (PublicKeyDataObject)obj;
        }
        if (obj != null)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(obj);
            ASN1ObjectIdentifier usage = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

            if (usage.on(EACObjectIdentifiers.id_TA_ECDSA))
            {
                return new ECDSAPublicKey(seq);
            }
            else
            {
                return new Asn1EacRSAPublicKey(seq);
            }
        }

        return null;
    }

    public abstract ASN1ObjectIdentifier getUsage();
}