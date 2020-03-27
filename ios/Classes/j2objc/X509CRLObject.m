//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/X509CRLObject.java
//

#include "ASN1Dump.h"
#include "ASN1Encodable.h"
#include "ASN1Encoding.h"
#include "ASN1InputStream.h"
#include "ASN1Integer.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "AlgorithmIdentifier.h"
#include "Asn1X509Time.h"
#include "BouncyCastleProvider.h"
#include "CRLDistPoint.h"
#include "CRLNumber.h"
#include "CertificateList.h"
#include "DERBitString.h"
#include "ExtCRLException.h"
#include "Extension.h"
#include "Extensions.h"
#include "GeneralName.h"
#include "GeneralNames.h"
#include "Hex.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "IssuingDistributionPoint.h"
#include "J2ObjC_source.h"
#include "RFC3280CertPathUtilities.h"
#include "Strings.h"
#include "TBSCertList.h"
#include "X500Name.h"
#include "X509CRLEntryObject.h"
#include "X509CRLObject.h"
#include "X509Certificate.h"
#include "X509Principal.h"
#include "X509SignatureUtil.h"
#include "java/io/IOException.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/RuntimeException.h"
#include "java/lang/StringBuffer.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"
#include "java/security/Principal.h"
#include "java/security/Provider.h"
#include "java/security/PublicKey.h"
#include "java/security/Signature.h"
#include "java/security/SignatureException.h"
#include "java/security/cert/CRLException.h"
#include "java/security/cert/Certificate.h"
#include "java/security/cert/CertificateEncodingException.h"
#include "java/security/cert/X509CRL.h"
#include "java/security/cert/X509CRLEntry.h"
#include "java/security/cert/X509Certificate.h"
#include "java/util/Collections.h"
#include "java/util/Date.h"
#include "java/util/Enumeration.h"
#include "java/util/HashSet.h"
#include "java/util/Iterator.h"
#include "java/util/Set.h"
#include "javax/security/auth/x500/X500Principal.h"

@interface LibOrgBouncycastleJceProviderX509CRLObject () {
 @public
  LibOrgBouncycastleAsn1X509CertificateList *c_;
  NSString *sigAlgName_;
  IOSByteArray *sigAlgParams_;
  jboolean isIndirect_;
  jboolean isHashCodeSet_;
  jint hashCodeValue_;
}

- (id<JavaUtilSet>)getExtensionOIDsWithBoolean:(jboolean)critical;

- (void)doVerifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key
                withJavaSecuritySignature:(JavaSecuritySignature *)sig;

- (id<JavaUtilSet>)loadCRLEntries;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderX509CRLObject, c_, LibOrgBouncycastleAsn1X509CertificateList *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderX509CRLObject, sigAlgName_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderX509CRLObject, sigAlgParams_, IOSByteArray *)

__attribute__((unused)) static id<JavaUtilSet> LibOrgBouncycastleJceProviderX509CRLObject_getExtensionOIDsWithBoolean_(LibOrgBouncycastleJceProviderX509CRLObject *self, jboolean critical);

__attribute__((unused)) static void LibOrgBouncycastleJceProviderX509CRLObject_doVerifyWithJavaSecurityPublicKey_withJavaSecuritySignature_(LibOrgBouncycastleJceProviderX509CRLObject *self, id<JavaSecurityPublicKey> key, JavaSecuritySignature *sig);

__attribute__((unused)) static id<JavaUtilSet> LibOrgBouncycastleJceProviderX509CRLObject_loadCRLEntries(LibOrgBouncycastleJceProviderX509CRLObject *self);

@implementation LibOrgBouncycastleJceProviderX509CRLObject

+ (jboolean)isIndirectCRLWithJavaSecurityCertX509CRL:(JavaSecurityCertX509CRL *)crl {
  return LibOrgBouncycastleJceProviderX509CRLObject_isIndirectCRLWithJavaSecurityCertX509CRL_(crl);
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509CertificateList:(LibOrgBouncycastleAsn1X509CertificateList *)c {
  LibOrgBouncycastleJceProviderX509CRLObject_initWithLibOrgBouncycastleAsn1X509CertificateList_(self, c);
  return self;
}

- (jboolean)hasUnsupportedCriticalExtension {
  id<JavaUtilSet> extns = [self getCriticalExtensionOIDs];
  if (extns == nil) {
    return false;
  }
  [extns removeWithId:JreLoadStatic(LibOrgBouncycastleJceProviderRFC3280CertPathUtilities, ISSUING_DISTRIBUTION_POINT)];
  [extns removeWithId:JreLoadStatic(LibOrgBouncycastleJceProviderRFC3280CertPathUtilities, DELTA_CRL_INDICATOR)];
  return ![extns isEmpty];
}

- (id<JavaUtilSet>)getExtensionOIDsWithBoolean:(jboolean)critical {
  return LibOrgBouncycastleJceProviderX509CRLObject_getExtensionOIDsWithBoolean_(self, critical);
}

- (id<JavaUtilSet>)getCriticalExtensionOIDs {
  return LibOrgBouncycastleJceProviderX509CRLObject_getExtensionOIDsWithBoolean_(self, true);
}

- (id<JavaUtilSet>)getNonCriticalExtensionOIDs {
  return LibOrgBouncycastleJceProviderX509CRLObject_getExtensionOIDsWithBoolean_(self, false);
}

- (IOSByteArray *)getExtensionValueWithNSString:(NSString *)oid {
  LibOrgBouncycastleAsn1X509Extensions *exts = [((LibOrgBouncycastleAsn1X509TBSCertList *) nil_chk([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getTBSCertList])) getExtensions];
  if (exts != nil) {
    LibOrgBouncycastleAsn1X509Extension *ext = [exts getExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(oid)];
    if (ext != nil) {
      @try {
        return [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk([ext getExtnValue])) getEncoded];
      }
      @catch (JavaLangException *e) {
        @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", @"error parsing ", [e description]));
      }
    }
  }
  return nil;
}

- (IOSByteArray *)getEncoded {
  @try {
    return [((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaSecurityCertCRLException_initWithNSString_([e description]);
  }
}

- (void)verifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key {
  JavaSecuritySignature *sig;
  @try {
    sig = JavaSecuritySignature_getInstanceWithNSString_withNSString_([self getSigAlgName], LibOrgBouncycastleJceProviderBouncyCastleProvider_PROVIDER_NAME);
  }
  @catch (JavaLangException *e) {
    sig = JavaSecuritySignature_getInstanceWithNSString_([self getSigAlgName]);
  }
  LibOrgBouncycastleJceProviderX509CRLObject_doVerifyWithJavaSecurityPublicKey_withJavaSecuritySignature_(self, key, sig);
}

- (void)verifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key
                           withNSString:(NSString *)sigProvider {
  JavaSecuritySignature *sig;
  if (sigProvider != nil) {
    sig = JavaSecuritySignature_getInstanceWithNSString_withNSString_([self getSigAlgName], sigProvider);
  }
  else {
    sig = JavaSecuritySignature_getInstanceWithNSString_([self getSigAlgName]);
  }
  LibOrgBouncycastleJceProviderX509CRLObject_doVerifyWithJavaSecurityPublicKey_withJavaSecuritySignature_(self, key, sig);
}

- (void)verifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key
               withJavaSecurityProvider:(JavaSecurityProvider *)sigProvider {
  JavaSecuritySignature *sig;
  if (sigProvider != nil) {
    sig = JavaSecuritySignature_getInstanceWithNSString_withJavaSecurityProvider_([self getSigAlgName], sigProvider);
  }
  else {
    sig = JavaSecuritySignature_getInstanceWithNSString_([self getSigAlgName]);
  }
  LibOrgBouncycastleJceProviderX509CRLObject_doVerifyWithJavaSecurityPublicKey_withJavaSecuritySignature_(self, key, sig);
}

- (void)doVerifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key
                withJavaSecuritySignature:(JavaSecuritySignature *)sig {
  LibOrgBouncycastleJceProviderX509CRLObject_doVerifyWithJavaSecurityPublicKey_withJavaSecuritySignature_(self, key, sig);
}

- (jint)getVersion {
  return [((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getVersionNumber];
}

- (id<JavaSecurityPrincipal>)getIssuerDN {
  return new_LibOrgBouncycastleJceX509Principal_initWithLibOrgBouncycastleAsn1X500X500Name_(LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([((LibOrgBouncycastleAsn1X500X500Name *) nil_chk([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getIssuer])) toASN1Primitive]));
}

- (JavaxSecurityAuthX500X500Principal *)getIssuerX500Principal {
  @try {
    return new_JavaxSecurityAuthX500X500Principal_initWithByteArray_([((LibOrgBouncycastleAsn1X500X500Name *) nil_chk([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getIssuer])) getEncoded]);
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"can't encode issuer DN");
  }
}

- (JavaUtilDate *)getThisUpdate {
  return [((LibOrgBouncycastleAsn1X509Asn1X509Time *) nil_chk([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getThisUpdate])) getDate];
}

- (JavaUtilDate *)getNextUpdate {
  if ([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getNextUpdate] != nil) {
    return [((LibOrgBouncycastleAsn1X509Asn1X509Time *) nil_chk([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getNextUpdate])) getDate];
  }
  return nil;
}

- (id<JavaUtilSet>)loadCRLEntries {
  return LibOrgBouncycastleJceProviderX509CRLObject_loadCRLEntries(self);
}

- (JavaSecurityCertX509CRLEntry *)getRevokedCertificateWithJavaMathBigInteger:(JavaMathBigInteger *)serialNumber {
  id<JavaUtilEnumeration> certs = [((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getRevokedCertificateEnumeration];
  LibOrgBouncycastleAsn1X500X500Name *previousCertificateIssuer = nil;
  while ([((id<JavaUtilEnumeration>) nil_chk(certs)) hasMoreElements]) {
    LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *entry_ = (LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *) cast_chk([certs nextElement], [LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry class]);
    if ([((JavaMathBigInteger *) nil_chk(serialNumber)) isEqual:[((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk([((LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *) nil_chk(entry_)) getUserCertificate])) getValue]]) {
      return new_LibOrgBouncycastleJceProviderX509CRLEntryObject_initWithLibOrgBouncycastleAsn1X509TBSCertList_CRLEntry_withBoolean_withLibOrgBouncycastleAsn1X500X500Name_(entry_, isIndirect_, previousCertificateIssuer);
    }
    if (isIndirect_ && [entry_ hasExtensions]) {
      LibOrgBouncycastleAsn1X509Extension *currentCaName = [((LibOrgBouncycastleAsn1X509Extensions *) nil_chk([entry_ getExtensions])) getExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, certificateIssuer)];
      if (currentCaName != nil) {
        previousCertificateIssuer = LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([((LibOrgBouncycastleAsn1X509GeneralName *) nil_chk(IOSObjectArray_Get(nil_chk([((LibOrgBouncycastleAsn1X509GeneralNames *) nil_chk(LibOrgBouncycastleAsn1X509GeneralNames_getInstanceWithId_([currentCaName getParsedValue]))) getNames]), 0))) getName]);
      }
    }
  }
  return nil;
}

- (id<JavaUtilSet>)getRevokedCertificates {
  id<JavaUtilSet> entrySet = LibOrgBouncycastleJceProviderX509CRLObject_loadCRLEntries(self);
  if (![((id<JavaUtilSet>) nil_chk(entrySet)) isEmpty]) {
    return JavaUtilCollections_unmodifiableSetWithJavaUtilSet_(entrySet);
  }
  return nil;
}

- (IOSByteArray *)getTBSCertList {
  @try {
    return [((LibOrgBouncycastleAsn1X509TBSCertList *) nil_chk([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getTBSCertList])) getEncodedWithNSString:@"DER"];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaSecurityCertCRLException_initWithNSString_([e description]);
  }
}

- (IOSByteArray *)getSignature {
  return [((LibOrgBouncycastleAsn1DERBitString *) nil_chk([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getSignature])) getOctets];
}

- (NSString *)getSigAlgName {
  return sigAlgName_;
}

- (NSString *)getSigAlgOID {
  return [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getSignatureAlgorithm])) getAlgorithm])) getId];
}

- (IOSByteArray *)getSigAlgParams {
  if (sigAlgParams_ != nil) {
    IOSByteArray *tmp = [IOSByteArray newArrayWithLength:sigAlgParams_->size_];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(sigAlgParams_, 0, tmp, 0, tmp->size_);
    return tmp;
  }
  return nil;
}

- (NSString *)description {
  JavaLangStringBuffer *buf = new_JavaLangStringBuffer_init();
  NSString *nl = LibOrgBouncycastleUtilStrings_lineSeparator();
  (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@"              Version: "])) appendWithInt:[self getVersion]])) appendWithNSString:nl];
  (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@"             IssuerDN: "])) appendWithId:[self getIssuerDN]])) appendWithNSString:nl];
  (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@"          This update: "])) appendWithId:[self getThisUpdate]])) appendWithNSString:nl];
  (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@"          Next update: "])) appendWithId:[self getNextUpdate]])) appendWithNSString:nl];
  (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@"  Signature Algorithm: "])) appendWithNSString:[self getSigAlgName]])) appendWithNSString:nl];
  IOSByteArray *sig = [self getSignature];
  (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@"            Signature: "])) appendWithNSString:[NSString java_stringWithBytes:LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_withInt_withInt_(sig, 0, 20)]])) appendWithNSString:nl];
  for (jint i = 20; i < ((IOSByteArray *) nil_chk(sig))->size_; i += 20) {
    if (i < sig->size_ - 20) {
      (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@"                       "])) appendWithNSString:[NSString java_stringWithBytes:LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_withInt_withInt_(sig, i, 20)]])) appendWithNSString:nl];
    }
    else {
      (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@"                       "])) appendWithNSString:[NSString java_stringWithBytes:LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_withInt_withInt_(sig, i, sig->size_ - i)]])) appendWithNSString:nl];
    }
  }
  LibOrgBouncycastleAsn1X509Extensions *extensions = [((LibOrgBouncycastleAsn1X509TBSCertList *) nil_chk([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getTBSCertList])) getExtensions];
  if (extensions != nil) {
    id<JavaUtilEnumeration> e = [extensions oids];
    if ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
      (void) [((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@"           Extensions: "])) appendWithNSString:nl];
    }
    while ([e hasMoreElements]) {
      LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
      LibOrgBouncycastleAsn1X509Extension *ext = [extensions getExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:oid];
      if ([((LibOrgBouncycastleAsn1X509Extension *) nil_chk(ext)) getExtnValue] != nil) {
        IOSByteArray *octs = [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk([ext getExtnValue])) getOctets];
        LibOrgBouncycastleAsn1ASN1InputStream *dIn = new_LibOrgBouncycastleAsn1ASN1InputStream_initWithByteArray_(octs);
        (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@"                       critical("])) appendWithBoolean:[ext isCritical]])) appendWithNSString:@") "];
        @try {
          if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(oid)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, cRLNumber)]) {
            (void) [((JavaLangStringBuffer *) nil_chk([buf appendWithId:new_LibOrgBouncycastleAsn1X509CRLNumber_initWithJavaMathBigInteger_([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([dIn readObject]))) getPositiveValue])])) appendWithNSString:nl];
          }
          else if ([oid isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, deltaCRLIndicator)]) {
            (void) [((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:JreStrcat("$@", @"Base CRL: ", new_LibOrgBouncycastleAsn1X509CRLNumber_initWithJavaMathBigInteger_([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([dIn readObject]))) getPositiveValue]))])) appendWithNSString:nl];
          }
          else if ([oid isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, issuingDistributionPoint)]) {
            (void) [((JavaLangStringBuffer *) nil_chk([buf appendWithId:LibOrgBouncycastleAsn1X509IssuingDistributionPoint_getInstanceWithId_([dIn readObject])])) appendWithNSString:nl];
          }
          else if ([oid isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, cRLDistributionPoints)]) {
            (void) [((JavaLangStringBuffer *) nil_chk([buf appendWithId:LibOrgBouncycastleAsn1X509CRLDistPoint_getInstanceWithId_([dIn readObject])])) appendWithNSString:nl];
          }
          else if ([oid isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, freshestCRL)]) {
            (void) [((JavaLangStringBuffer *) nil_chk([buf appendWithId:LibOrgBouncycastleAsn1X509CRLDistPoint_getInstanceWithId_([dIn readObject])])) appendWithNSString:nl];
          }
          else {
            (void) [buf appendWithNSString:[oid getId]];
            (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@" value = "])) appendWithNSString:LibOrgBouncycastleAsn1UtilASN1Dump_dumpAsStringWithId_([dIn readObject])])) appendWithNSString:nl];
          }
        }
        @catch (JavaLangException *ex) {
          (void) [buf appendWithNSString:[oid getId]];
          (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@" value = "])) appendWithNSString:@"*****"])) appendWithNSString:nl];
        }
      }
      else {
        (void) [buf appendWithNSString:nl];
      }
    }
  }
  id<JavaUtilSet> set = [self getRevokedCertificates];
  if (set != nil) {
    id<JavaUtilIterator> it = [set iterator];
    while ([((id<JavaUtilIterator>) nil_chk(it)) hasNext]) {
      (void) [buf appendWithId:[it next]];
      (void) [buf appendWithNSString:nl];
    }
  }
  return [buf description];
}

- (jboolean)isRevokedWithJavaSecurityCertCertificate:(JavaSecurityCertCertificate *)cert {
  if (![((NSString *) nil_chk([((JavaSecurityCertCertificate *) nil_chk(cert)) getType])) isEqual:@"X.509"]) {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"X.509 CRL used with non X.509 Cert");
  }
  id<JavaUtilEnumeration> certs = [((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getRevokedCertificateEnumeration];
  LibOrgBouncycastleAsn1X500X500Name *caName = [((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c_)) getIssuer];
  if (certs != nil) {
    JavaMathBigInteger *serial = [((JavaSecurityCertX509Certificate *) cast_chk(cert, [JavaSecurityCertX509Certificate class])) getSerialNumber];
    while ([certs hasMoreElements]) {
      LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *entry_ = LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry_getInstanceWithId_([certs nextElement]);
      if (isIndirect_ && [((LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *) nil_chk(entry_)) hasExtensions]) {
        LibOrgBouncycastleAsn1X509Extension *currentCaName = [((LibOrgBouncycastleAsn1X509Extensions *) nil_chk([((LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *) nil_chk(entry_)) getExtensions])) getExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, certificateIssuer)];
        if (currentCaName != nil) {
          caName = LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([((LibOrgBouncycastleAsn1X509GeneralName *) nil_chk(IOSObjectArray_Get(nil_chk([((LibOrgBouncycastleAsn1X509GeneralNames *) nil_chk(LibOrgBouncycastleAsn1X509GeneralNames_getInstanceWithId_([currentCaName getParsedValue]))) getNames]), 0))) getName]);
        }
      }
      if ([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk([((LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *) nil_chk(entry_)) getUserCertificate])) getValue])) isEqual:serial]) {
        LibOrgBouncycastleAsn1X500X500Name *issuer;
        if ([cert isKindOfClass:[JavaSecurityCertX509Certificate class]]) {
          issuer = LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([((JavaxSecurityAuthX500X500Principal *) nil_chk([((JavaSecurityCertX509Certificate *) cert) getIssuerX500Principal])) getEncoded]);
        }
        else {
          @try {
            issuer = [((LibOrgBouncycastleAsn1X509X509Certificate *) nil_chk(LibOrgBouncycastleAsn1X509X509Certificate_getInstanceWithId_([cert getEncoded]))) getIssuer];
          }
          @catch (JavaSecurityCertCertificateEncodingException *e) {
            @throw new_JavaLangRuntimeException_initWithNSString_(@"Cannot process certificate");
          }
        }
        if (![((LibOrgBouncycastleAsn1X500X500Name *) nil_chk(caName)) isEqual:issuer]) {
          return false;
        }
        return true;
      }
    }
  }
  return false;
}

- (jboolean)isEqual:(id)other {
  if (self == other) {
    return true;
  }
  if (!([other isKindOfClass:[JavaSecurityCertX509CRL class]])) {
    return false;
  }
  if ([other isKindOfClass:[LibOrgBouncycastleJceProviderX509CRLObject class]]) {
    LibOrgBouncycastleJceProviderX509CRLObject *crlObject = (LibOrgBouncycastleJceProviderX509CRLObject *) other;
    if (isHashCodeSet_) {
      jboolean otherIsHashCodeSet = ((LibOrgBouncycastleJceProviderX509CRLObject *) nil_chk(crlObject))->isHashCodeSet_;
      if (otherIsHashCodeSet) {
        if (crlObject->hashCodeValue_ != hashCodeValue_) {
          return false;
        }
      }
    }
    return [((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(self->c_)) isEqual:((LibOrgBouncycastleJceProviderX509CRLObject *) nil_chk(crlObject))->c_];
  }
  return [super isEqual:other];
}

- (NSUInteger)hash {
  if (!isHashCodeSet_) {
    isHashCodeSet_ = true;
    hashCodeValue_ = ((jint) [super hash]);
  }
  return hashCodeValue_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "Z", 0x9, 0, 1, 2, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, 2, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x2, 4, 5, -1, -1, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 8, 9, 10, -1, -1, -1 },
    { NULL, "V", 0x1, 8, 11, 10, -1, -1, -1 },
    { NULL, "V", 0x1, 8, 12, 13, -1, -1, -1 },
    { NULL, "V", 0x2, 14, 15, 13, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityPrincipal;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaxSecurityAuthX500X500Principal;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilDate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilDate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityCertX509CRLEntry;", 0x1, 16, 17, -1, -1, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 18, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 19, 20, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 21, 22, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 23, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(isIndirectCRLWithJavaSecurityCertX509CRL:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1X509CertificateList:);
  methods[2].selector = @selector(hasUnsupportedCriticalExtension);
  methods[3].selector = @selector(getExtensionOIDsWithBoolean:);
  methods[4].selector = @selector(getCriticalExtensionOIDs);
  methods[5].selector = @selector(getNonCriticalExtensionOIDs);
  methods[6].selector = @selector(getExtensionValueWithNSString:);
  methods[7].selector = @selector(getEncoded);
  methods[8].selector = @selector(verifyWithJavaSecurityPublicKey:);
  methods[9].selector = @selector(verifyWithJavaSecurityPublicKey:withNSString:);
  methods[10].selector = @selector(verifyWithJavaSecurityPublicKey:withJavaSecurityProvider:);
  methods[11].selector = @selector(doVerifyWithJavaSecurityPublicKey:withJavaSecuritySignature:);
  methods[12].selector = @selector(getVersion);
  methods[13].selector = @selector(getIssuerDN);
  methods[14].selector = @selector(getIssuerX500Principal);
  methods[15].selector = @selector(getThisUpdate);
  methods[16].selector = @selector(getNextUpdate);
  methods[17].selector = @selector(loadCRLEntries);
  methods[18].selector = @selector(getRevokedCertificateWithJavaMathBigInteger:);
  methods[19].selector = @selector(getRevokedCertificates);
  methods[20].selector = @selector(getTBSCertList);
  methods[21].selector = @selector(getSignature);
  methods[22].selector = @selector(getSigAlgName);
  methods[23].selector = @selector(getSigAlgOID);
  methods[24].selector = @selector(getSigAlgParams);
  methods[25].selector = @selector(description);
  methods[26].selector = @selector(isRevokedWithJavaSecurityCertCertificate:);
  methods[27].selector = @selector(isEqual:);
  methods[28].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "c_", "LLibOrgBouncycastleAsn1X509CertificateList;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sigAlgName_", "LNSString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sigAlgParams_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "isIndirect_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "isHashCodeSet_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hashCodeValue_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "isIndirectCRL", "LJavaSecurityCertX509CRL;", "LJavaSecurityCertCRLException;", "LLibOrgBouncycastleAsn1X509CertificateList;", "getExtensionOIDs", "Z", "getExtensionValue", "LNSString;", "verify", "LJavaSecurityPublicKey;", "LJavaSecurityCertCRLException;LJavaSecurityNoSuchAlgorithmException;LJavaSecurityInvalidKeyException;LJavaSecurityNoSuchProviderException;LJavaSecuritySignatureException;", "LJavaSecurityPublicKey;LNSString;", "LJavaSecurityPublicKey;LJavaSecurityProvider;", "LJavaSecurityCertCRLException;LJavaSecurityNoSuchAlgorithmException;LJavaSecurityInvalidKeyException;LJavaSecuritySignatureException;", "doVerify", "LJavaSecurityPublicKey;LJavaSecuritySignature;", "getRevokedCertificate", "LJavaMathBigInteger;", "toString", "isRevoked", "LJavaSecurityCertCertificate;", "equals", "LNSObject;", "hashCode" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceProviderX509CRLObject = { "X509CRLObject", "lib.org.bouncycastle.jce.provider", ptrTable, methods, fields, 7, 0x1, 29, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceProviderX509CRLObject;
}

@end

jboolean LibOrgBouncycastleJceProviderX509CRLObject_isIndirectCRLWithJavaSecurityCertX509CRL_(JavaSecurityCertX509CRL *crl) {
  LibOrgBouncycastleJceProviderX509CRLObject_initialize();
  @try {
    IOSByteArray *idp = [((JavaSecurityCertX509CRL *) nil_chk(crl)) getExtensionValueWithNSString:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, issuingDistributionPoint))) getId]];
    return idp != nil && [((LibOrgBouncycastleAsn1X509IssuingDistributionPoint *) nil_chk(LibOrgBouncycastleAsn1X509IssuingDistributionPoint_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_(idp))) getOctets]))) isIndirectCRL];
  }
  @catch (JavaLangException *e) {
    @throw new_LibOrgBouncycastleJceProviderExtCRLException_initWithNSString_withJavaLangThrowable_(@"Exception reading IssuingDistributionPoint", e);
  }
}

void LibOrgBouncycastleJceProviderX509CRLObject_initWithLibOrgBouncycastleAsn1X509CertificateList_(LibOrgBouncycastleJceProviderX509CRLObject *self, LibOrgBouncycastleAsn1X509CertificateList *c) {
  JavaSecurityCertX509CRL_init(self);
  self->isHashCodeSet_ = false;
  self->c_ = c;
  @try {
    self->sigAlgName_ = LibOrgBouncycastleJceProviderX509SignatureUtil_getSignatureNameWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(c)) getSignatureAlgorithm]);
    if ([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([c getSignatureAlgorithm])) getParameters] != nil) {
      self->sigAlgParams_ = [((LibOrgBouncycastleAsn1ASN1Primitive *) nil_chk([((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([c getSignatureAlgorithm])) getParameters]))) toASN1Primitive])) getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
    }
    else {
      self->sigAlgParams_ = nil;
    }
    self->isIndirect_ = LibOrgBouncycastleJceProviderX509CRLObject_isIndirectCRLWithJavaSecurityCertX509CRL_(self);
  }
  @catch (JavaLangException *e) {
    @throw new_JavaSecurityCertCRLException_initWithNSString_(JreStrcat("$@", @"CRL contents invalid: ", e));
  }
}

LibOrgBouncycastleJceProviderX509CRLObject *new_LibOrgBouncycastleJceProviderX509CRLObject_initWithLibOrgBouncycastleAsn1X509CertificateList_(LibOrgBouncycastleAsn1X509CertificateList *c) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderX509CRLObject, initWithLibOrgBouncycastleAsn1X509CertificateList_, c)
}

LibOrgBouncycastleJceProviderX509CRLObject *create_LibOrgBouncycastleJceProviderX509CRLObject_initWithLibOrgBouncycastleAsn1X509CertificateList_(LibOrgBouncycastleAsn1X509CertificateList *c) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderX509CRLObject, initWithLibOrgBouncycastleAsn1X509CertificateList_, c)
}

id<JavaUtilSet> LibOrgBouncycastleJceProviderX509CRLObject_getExtensionOIDsWithBoolean_(LibOrgBouncycastleJceProviderX509CRLObject *self, jboolean critical) {
  if ([self getVersion] == 2) {
    LibOrgBouncycastleAsn1X509Extensions *extensions = [((LibOrgBouncycastleAsn1X509TBSCertList *) nil_chk([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(self->c_)) getTBSCertList])) getExtensions];
    if (extensions != nil) {
      id<JavaUtilSet> set = new_JavaUtilHashSet_init();
      id<JavaUtilEnumeration> e = [extensions oids];
      while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
        LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
        LibOrgBouncycastleAsn1X509Extension *ext = [extensions getExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:oid];
        if (critical == [((LibOrgBouncycastleAsn1X509Extension *) nil_chk(ext)) isCritical]) {
          [set addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(oid)) getId]];
        }
      }
      return set;
    }
  }
  return nil;
}

void LibOrgBouncycastleJceProviderX509CRLObject_doVerifyWithJavaSecurityPublicKey_withJavaSecuritySignature_(LibOrgBouncycastleJceProviderX509CRLObject *self, id<JavaSecurityPublicKey> key, JavaSecuritySignature *sig) {
  if (![((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(self->c_)) getSignatureAlgorithm])) isEqual:[((LibOrgBouncycastleAsn1X509TBSCertList *) nil_chk([((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(self->c_)) getTBSCertList])) getSignature]]) {
    @throw new_JavaSecurityCertCRLException_initWithNSString_(@"Signature algorithm on CertificateList does not match TBSCertList.");
  }
  [((JavaSecuritySignature *) nil_chk(sig)) initVerifyWithJavaSecurityPublicKey:key];
  [sig updateWithByteArray:[self getTBSCertList]];
  if (![sig verifyWithByteArray:[self getSignature]]) {
    @throw new_JavaSecuritySignatureException_initWithNSString_(@"CRL does not verify with supplied public key.");
  }
}

id<JavaUtilSet> LibOrgBouncycastleJceProviderX509CRLObject_loadCRLEntries(LibOrgBouncycastleJceProviderX509CRLObject *self) {
  id<JavaUtilSet> entrySet = new_JavaUtilHashSet_init();
  id<JavaUtilEnumeration> certs = [((LibOrgBouncycastleAsn1X509CertificateList *) nil_chk(self->c_)) getRevokedCertificateEnumeration];
  LibOrgBouncycastleAsn1X500X500Name *previousCertificateIssuer = nil;
  while ([((id<JavaUtilEnumeration>) nil_chk(certs)) hasMoreElements]) {
    LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *entry_ = (LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *) cast_chk([certs nextElement], [LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry class]);
    LibOrgBouncycastleJceProviderX509CRLEntryObject *crlEntry = new_LibOrgBouncycastleJceProviderX509CRLEntryObject_initWithLibOrgBouncycastleAsn1X509TBSCertList_CRLEntry_withBoolean_withLibOrgBouncycastleAsn1X500X500Name_(entry_, self->isIndirect_, previousCertificateIssuer);
    [entrySet addWithId:crlEntry];
    if (self->isIndirect_ && [((LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *) nil_chk(entry_)) hasExtensions]) {
      LibOrgBouncycastleAsn1X509Extension *currentCaName = [((LibOrgBouncycastleAsn1X509Extensions *) nil_chk([((LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *) nil_chk(entry_)) getExtensions])) getExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, certificateIssuer)];
      if (currentCaName != nil) {
        previousCertificateIssuer = LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([((LibOrgBouncycastleAsn1X509GeneralName *) nil_chk(IOSObjectArray_Get(nil_chk([((LibOrgBouncycastleAsn1X509GeneralNames *) nil_chk(LibOrgBouncycastleAsn1X509GeneralNames_getInstanceWithId_([currentCaName getParsedValue]))) getNames]), 0))) getName]);
      }
    }
  }
  return entrySet;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceProviderX509CRLObject)
