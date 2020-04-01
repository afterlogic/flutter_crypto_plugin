package lib.org.bouncycastle.asn1.cms;

import lib.org.bouncycastle.asn1.ASN1EncodableVector;
import lib.org.bouncycastle.asn1.ASN1Integer;
import lib.org.bouncycastle.asn1.ASN1Object;
import lib.org.bouncycastle.asn1.ASN1Primitive;
import lib.org.bouncycastle.asn1.ASN1Sequence;
import lib.org.bouncycastle.asn1.ASN1TaggedObject;
import lib.org.bouncycastle.asn1.BERSequence;
import lib.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/** 
 * <a href="http://tools.ietf.org/html/rfc3274">RFC 3274</a>: CMS Compressed Data.
 * 
 * <pre>
 * CompressedData ::= SEQUENCE {
 *     version CMSVersion,
 *     compressionAlgorithm CompressionAlgorithmIdentifier,
 *     encapContentInfo EncapsulatedContentInfo
 * }
 * </pre>
 */
public class CompressedData
    extends ASN1Object
{
    private ASN1Integer           version;
    private AlgorithmIdentifier  compressionAlgorithm;
    private Asn1CmsContentInfo encapContentInfo;

    public CompressedData(
        AlgorithmIdentifier compressionAlgorithm,
        Asn1CmsContentInfo encapContentInfo)
    {
        this.version = new ASN1Integer(0);
        this.compressionAlgorithm = compressionAlgorithm;
        this.encapContentInfo = encapContentInfo;
    }
    
    private CompressedData(
        ASN1Sequence seq)
    {
        this.version = (ASN1Integer)seq.getObjectAt(0);
        this.compressionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.encapContentInfo = Asn1CmsContentInfo.getInstance(seq.getObjectAt(2));
    }

    /**
     * Return a CompressedData object from a tagged object.
     *
     * @param ato the tagged object holding the object we want.
     * @param isExplicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static CompressedData getInstance(
        ASN1TaggedObject ato,
        boolean isExplicit)
    {
        return getInstance(ASN1Sequence.getInstance(ato, isExplicit));
    }
    
    /**
     * Return a CompressedData object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link CompressedData} object
     * <li> {@link ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with CompressedData structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static CompressedData getInstance(
        Object obj)
    {
        if (obj instanceof CompressedData)
        {
            return (CompressedData)obj;
        }

        if (obj != null)
        {
            return new CompressedData(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public AlgorithmIdentifier getCompressionAlgorithmIdentifier()
    {
        return compressionAlgorithm;
    }

    public Asn1CmsContentInfo getEncapContentInfo()
    {
        return encapContentInfo;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(compressionAlgorithm);
        v.add(encapContentInfo);

        return new BERSequence(v);
    }
}