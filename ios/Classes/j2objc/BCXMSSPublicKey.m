//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/xmss/BCXMSSPublicKey.java
//

#include "ASN1Encodable.h"
#include "ASN1ObjectIdentifier.h"
#include "AlgorithmIdentifier.h"
#include "Arrays.h"
#include "AsymmetricKeyParameter.h"
#include "BCXMSSPublicKey.h"
#include "CipherParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PqcCryptoPublicKeyFactory.h"
#include "PqcJcajceXmssDigestUtil.h"
#include "PqcSubjectPublicKeyInfoFactory.h"
#include "SubjectPublicKeyInfo.h"
#include "XMSSKeyParams.h"
#include "XMSSParameters.h"
#include "XMSSPublicKeyParameters.h"
#include "java/io/IOException.h"
#include "java/io/ObjectInputStream.h"
#include "java/io/ObjectOutputStream.h"

@interface LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey () {
 @public
  LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *keyParams_;
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest_;
}

- (void)init__WithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)keyInfo OBJC_METHOD_FAMILY_NONE;

- (void)readObjectWithJavaIoObjectInputStream:(JavaIoObjectInputStream *)inArg;

- (void)writeObjectWithJavaIoObjectOutputStream:(JavaIoObjectOutputStream *)outArg;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey, keyParams_, LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey, treeDigest_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline jlong LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_get_serialVersionUID(void);
#define LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_serialVersionUID -5617456225328969766LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey, serialVersionUID, jlong)

__attribute__((unused)) static void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_init__WithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *self, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *keyInfo);

__attribute__((unused)) static void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_readObjectWithJavaIoObjectInputStream_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *self, JavaIoObjectInputStream *inArg);

__attribute__((unused)) static void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_writeObjectWithJavaIoObjectOutputStream_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *self, JavaIoObjectOutputStream *outArg);

@implementation LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)treeDigest
        withLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *)keyParams {
  LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_(self, treeDigest, keyParams);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)keyInfo {
  LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(self, keyInfo);
  return self;
}

- (void)init__WithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)keyInfo {
  LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_init__WithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(self, keyInfo);
}

- (NSString *)getAlgorithm {
  return @"PqcJcajceXMSS";
}

- (IOSByteArray *)getEncoded {
  @try {
    LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *pki = LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory_createSubjectPublicKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(keyParams_);
    return [((LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *) nil_chk(pki)) getEncoded];
  }
  @catch (JavaIoIOException *e) {
    return nil;
  }
}

- (NSString *)getFormat {
  return @"X.509";
}

- (id<LibOrgBouncycastleCryptoCipherParameters>)getKeyParams {
  return keyParams_;
}

- (jboolean)isEqual:(id)o {
  if (o == self) {
    return true;
  }
  if ([o isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey class]]) {
    LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *otherKey = (LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *) o;
    return [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(treeDigest_)) isEqual:((LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *) nil_chk(otherKey))->treeDigest_] && LibOrgBouncycastleUtilArrays_areEqualWithByteArray_withByteArray_([((LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *) nil_chk(keyParams_)) toByteArray], [((LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *) nil_chk(otherKey->keyParams_)) toByteArray]);
  }
  return false;
}

- (NSUInteger)hash {
  return ((jint) [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(treeDigest_)) hash]) + 37 * LibOrgBouncycastleUtilArrays_hashCodeWithByteArray_([((LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *) nil_chk(keyParams_)) toByteArray]);
}

- (jint)getHeight {
  return [((LibOrgBouncycastlePqcCryptoXmssXMSSParameters *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *) nil_chk(keyParams_)) getParameters])) getHeight];
}

- (NSString *)getTreeDigest {
  return LibOrgBouncycastlePqcJcajceProviderXmssPqcJcajceXmssDigestUtil_getXMSSDigestNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(treeDigest_);
}

- (void)readObjectWithJavaIoObjectInputStream:(JavaIoObjectInputStream *)inArg {
  LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_readObjectWithJavaIoObjectInputStream_(self, inArg);
}

- (void)writeObjectWithJavaIoObjectOutputStream:(JavaIoObjectOutputStream *)outArg {
  LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_writeObjectWithJavaIoObjectOutputStream_(self, outArg);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, 2, -1, -1, -1 },
    { NULL, "V", 0x2, 3, 1, 2, -1, -1, -1 },
    { NULL, "LNSString;", 0x11, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherParameters;", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 6, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 7, 8, 9, -1, -1, -1 },
    { NULL, "V", 0x2, 10, 11, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:);
  methods[2].selector = @selector(init__WithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:);
  methods[3].selector = @selector(getAlgorithm);
  methods[4].selector = @selector(getEncoded);
  methods[5].selector = @selector(getFormat);
  methods[6].selector = @selector(getKeyParams);
  methods[7].selector = @selector(isEqual:);
  methods[8].selector = @selector(hash);
  methods[9].selector = @selector(getHeight);
  methods[10].selector = @selector(getTreeDigest);
  methods[11].selector = @selector(readObjectWithJavaIoObjectInputStream:);
  methods[12].selector = @selector(writeObjectWithJavaIoObjectOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serialVersionUID", "J", .constantValue.asLong = LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_serialVersionUID, 0x1a, -1, -1, -1, -1 },
    { "keyParams_", "LLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters;", .constantValue.asLong = 0, 0x82, -1, -1, -1, -1 },
    { "treeDigest_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x82, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters;", "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;", "LJavaIoIOException;", "init", "equals", "LNSObject;", "hashCode", "readObject", "LJavaIoObjectInputStream;", "LJavaIoIOException;LJavaLangClassNotFoundException;", "writeObject", "LJavaIoObjectOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey = { "BCXMSSPublicKey", "lib.org.bouncycastle.pqc.jcajce.provider.xmss", ptrTable, methods, fields, 7, 0x1, 13, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey;
}

@end

void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *keyParams) {
  NSObject_init(self);
  self->treeDigest_ = treeDigest;
  self->keyParams_ = keyParams;
}

LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *new_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *keyParams) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_, treeDigest, keyParams)
}

LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *create_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *keyParams) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_, treeDigest, keyParams)
}

void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *self, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *keyInfo) {
  NSObject_init(self);
  LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_init__WithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(self, keyInfo);
}

LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *new_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *keyInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey, initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_, keyInfo)
}

LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *create_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *keyInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey, initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_, keyInfo)
}

void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_init__WithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *self, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *keyInfo) {
  LibOrgBouncycastlePqcAsn1XMSSKeyParams *keyParams = LibOrgBouncycastlePqcAsn1XMSSKeyParams_getInstanceWithId_([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *) nil_chk(keyInfo)) getAlgorithm])) getParameters]);
  self->treeDigest_ = [((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastlePqcAsn1XMSSKeyParams *) nil_chk(keyParams)) getTreeDigest])) getAlgorithm];
  self->keyParams_ = (LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *) cast_chk(LibOrgBouncycastlePqcCryptoUtilPqcCryptoPublicKeyFactory_createKeyWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(keyInfo), [LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters class]);
}

void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_readObjectWithJavaIoObjectInputStream_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *self, JavaIoObjectInputStream *inArg) {
  [((JavaIoObjectInputStream *) nil_chk(inArg)) defaultReadObject];
  IOSByteArray *enc = (IOSByteArray *) cast_chk([inArg readObject], [IOSByteArray class]);
  LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_init__WithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(self, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_getInstanceWithId_(enc));
}

void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey_writeObjectWithJavaIoObjectOutputStream_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey *self, JavaIoObjectOutputStream *outArg) {
  [((JavaIoObjectOutputStream *) nil_chk(outArg)) defaultWriteObject];
  [outArg writeObjectWithId:[self getEncoded]];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPublicKey)
