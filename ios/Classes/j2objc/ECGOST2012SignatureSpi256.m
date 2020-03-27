//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/ecgost12/ECGOST2012SignatureSpi256.java
//

#include "AsymmetricKeyParameter.h"
#include "BCECGOST3410_2012PublicKey.h"
#include "BouncyCastleProvider.h"
#include "DSAExt.h"
#include "Digest.h"
#include "ECDomainParameters.h"
#include "ECGOST2012SignatureSpi256.h"
#include "ECGOST3410_2012Signer.h"
#include "ECKey.h"
#include "ECKeyParameters.h"
#include "ECPublicKey.h"
#include "ECPublicKeyParameters.h"
#include "GOST3411_2012_256Digest.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcajceUtilECUtil.h"
#include "ParametersWithRandom.h"
#include "SubjectPublicKeyInfo.h"
#include "java/lang/Exception.h"
#include "java/lang/System.h"
#include "java/lang/UnsupportedOperationException.h"
#include "java/math/BigInteger.h"
#include "java/security/InvalidKeyException.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"
#include "java/security/SecureRandom.h"
#include "java/security/SignatureException.h"
#include "java/security/SignatureSpi.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256 () {
 @public
  id<LibOrgBouncycastleCryptoDigest> digest_;
  id<LibOrgBouncycastleCryptoDSAExt> signer_;
  jint size_;
  jint halfSize_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256, digest_, id<LibOrgBouncycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256, signer_, id<LibOrgBouncycastleCryptoDSAExt>)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)engineInitVerifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)publicKey {
  LibOrgBouncycastleCryptoParamsECKeyParameters *param;
  if ([LibOrgBouncycastleJceInterfacesECPublicKey_class_() isInstance:publicKey]) {
    param = (LibOrgBouncycastleCryptoParamsECKeyParameters *) cast_chk(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256_generatePublicKeyParameterWithJavaSecurityPublicKey_(publicKey), [LibOrgBouncycastleCryptoParamsECKeyParameters class]);
  }
  else {
    @try {
      IOSByteArray *bytes = [((id<JavaSecurityPublicKey>) nil_chk(publicKey)) getEncoded];
      publicKey = LibOrgBouncycastleJceProviderBouncyCastleProvider_getPublicKeyWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_getInstanceWithId_(bytes));
      param = (LibOrgBouncycastleCryptoParamsECKeyParameters *) cast_chk(LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilECUtil_generatePublicKeyParameterWithJavaSecurityPublicKey_(publicKey), [LibOrgBouncycastleCryptoParamsECKeyParameters class]);
    }
    @catch (JavaLangException *e) {
      @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"cannot recognise key type in ECGOST-2012-256 signer");
    }
  }
  if ([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsECKeyParameters *) nil_chk(param)) getParameters])) getN])) bitLength] > 256) {
    @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"key out of range for ECGOST-2012-256");
  }
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) reset];
  [((id<LibOrgBouncycastleCryptoDSAExt>) nil_chk(signer_)) init__WithBoolean:false withLibOrgBouncycastleCryptoCipherParameters:param];
}

- (void)engineInitSignWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privateKey {
  LibOrgBouncycastleCryptoParamsECKeyParameters *param;
  if ([LibOrgBouncycastleJceInterfacesECKey_class_() isInstance:privateKey]) {
    param = (LibOrgBouncycastleCryptoParamsECKeyParameters *) cast_chk(LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilECUtil_generatePrivateKeyParameterWithJavaSecurityPrivateKey_(privateKey), [LibOrgBouncycastleCryptoParamsECKeyParameters class]);
  }
  else {
    @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"cannot recognise key type in ECGOST-2012-256 signer");
  }
  if ([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsECKeyParameters *) nil_chk(param)) getParameters])) getN])) bitLength] > 256) {
    @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"key out of range for ECGOST-2012-256");
  }
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) reset];
  if (appRandom_ != nil) {
    [((id<LibOrgBouncycastleCryptoDSAExt>) nil_chk(signer_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsParametersWithRandom_initWithLibOrgBouncycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(param, appRandom_)];
  }
  else {
    [((id<LibOrgBouncycastleCryptoDSAExt>) nil_chk(signer_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:param];
  }
}

- (void)engineUpdateWithByte:(jbyte)b {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByte:b];
}

- (void)engineUpdateWithByteArray:(IOSByteArray *)b
                          withInt:(jint)off
                          withInt:(jint)len {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:b withInt:off withInt:len];
}

- (IOSByteArray *)engineSign {
  IOSByteArray *hash_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize]];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:hash_ withInt:0];
  @try {
    IOSByteArray *sigBytes = [IOSByteArray newArrayWithLength:size_];
    IOSObjectArray *sig = [((id<LibOrgBouncycastleCryptoDSAExt>) nil_chk(signer_)) generateSignatureWithByteArray:hash_];
    IOSByteArray *r = [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(nil_chk(sig), 0))) toByteArray];
    IOSByteArray *s = [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(sig, 1))) toByteArray];
    if (IOSByteArray_Get(nil_chk(s), 0) != 0) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(s, 0, sigBytes, halfSize_ - s->size_, s->size_);
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(s, 1, sigBytes, halfSize_ - (s->size_ - 1), s->size_ - 1);
    }
    if (IOSByteArray_Get(nil_chk(r), 0) != 0) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(r, 0, sigBytes, size_ - r->size_, r->size_);
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(r, 1, sigBytes, size_ - (r->size_ - 1), r->size_ - 1);
    }
    return sigBytes;
  }
  @catch (JavaLangException *e) {
    @throw new_JavaSecuritySignatureException_initWithNSString_([e description]);
  }
}

- (jboolean)engineVerifyWithByteArray:(IOSByteArray *)sigBytes {
  IOSByteArray *hash_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize]];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:hash_ withInt:0];
  IOSObjectArray *sig;
  @try {
    IOSByteArray *r = [IOSByteArray newArrayWithLength:halfSize_];
    IOSByteArray *s = [IOSByteArray newArrayWithLength:halfSize_];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(sigBytes, 0, s, 0, halfSize_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(sigBytes, halfSize_, r, 0, halfSize_);
    sig = [IOSObjectArray newArrayWithLength:2 type:JavaMathBigInteger_class_()];
    (void) IOSObjectArray_SetAndConsume(sig, 0, new_JavaMathBigInteger_initWithInt_withByteArray_(1, r));
    (void) IOSObjectArray_SetAndConsume(sig, 1, new_JavaMathBigInteger_initWithInt_withByteArray_(1, s));
  }
  @catch (JavaLangException *e) {
    @throw new_JavaSecuritySignatureException_initWithNSString_(@"error decoding signature bytes.");
  }
  return [((id<LibOrgBouncycastleCryptoDSAExt>) nil_chk(signer_)) verifySignatureWithByteArray:hash_ withJavaMathBigInteger:IOSObjectArray_Get(nil_chk(sig), 0) withJavaMathBigInteger:IOSObjectArray_Get(sig, 1)];
}

- (void)engineSetParameterWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params {
  @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"engineSetParameter unsupported");
}

- (void)engineSetParameterWithNSString:(NSString *)param
                                withId:(id)value {
  @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"engineSetParameter unsupported");
}

- (id)engineGetParameterWithNSString:(NSString *)param {
  @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"engineSetParameter unsupported");
}

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePublicKeyParameterWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key {
  return LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256_generatePublicKeyParameterWithJavaSecurityPublicKey_(key);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 0, 1, 2, -1, -1, -1 },
    { NULL, "V", 0x4, 3, 4, 2, -1, -1, -1 },
    { NULL, "V", 0x4, 5, 6, 7, -1, -1, -1 },
    { NULL, "V", 0x4, 5, 8, 7, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, 7, -1, -1, -1 },
    { NULL, "Z", 0x4, 9, 10, 7, -1, -1, -1 },
    { NULL, "V", 0x4, 11, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 11, 13, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x4, 14, 15, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x8, 16, 1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineInitVerifyWithJavaSecurityPublicKey:);
  methods[2].selector = @selector(engineInitSignWithJavaSecurityPrivateKey:);
  methods[3].selector = @selector(engineUpdateWithByte:);
  methods[4].selector = @selector(engineUpdateWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(engineSign);
  methods[6].selector = @selector(engineVerifyWithByteArray:);
  methods[7].selector = @selector(engineSetParameterWithJavaSecuritySpecAlgorithmParameterSpec:);
  methods[8].selector = @selector(engineSetParameterWithNSString:withId:);
  methods[9].selector = @selector(engineGetParameterWithNSString:);
  methods[10].selector = @selector(generatePublicKeyParameterWithJavaSecurityPublicKey:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "digest_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "signer_", "LLibOrgBouncycastleCryptoDSAExt;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "size_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "halfSize_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "engineInitVerify", "LJavaSecurityPublicKey;", "LJavaSecurityInvalidKeyException;", "engineInitSign", "LJavaSecurityPrivateKey;", "engineUpdate", "B", "LJavaSecuritySignatureException;", "[BII", "engineVerify", "[B", "engineSetParameter", "LJavaSecuritySpecAlgorithmParameterSpec;", "LNSString;LNSObject;", "engineGetParameter", "LNSString;", "generatePublicKeyParameter" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256 = { "ECGOST2012SignatureSpi256", "lib.org.bouncycastle.jcajce.provider.asymmetric.ecgost12", ptrTable, methods, fields, 7, 0x1, 11, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256_init(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256 *self) {
  JavaSecuritySignatureSpi_init(self);
  self->size_ = 64;
  self->halfSize_ = self->size_ / 2;
  self->digest_ = new_LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_init();
  self->signer_ = new_LibOrgBouncycastleCryptoSignersECGOST3410_2012Signer_init();
}

LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256 *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256 *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256, init)
}

LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256_generatePublicKeyParameterWithJavaSecurityPublicKey_(id<JavaSecurityPublicKey> key) {
  LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256_initialize();
  return ([key isKindOfClass:[LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey class]]) ? [((LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey *) nil_chk(((LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey *) cast_chk(key, [LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey class])))) engineGetKeyParameters] : LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilECUtil_generatePublicKeyParameterWithJavaSecurityPublicKey_(key);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12ECGOST2012SignatureSpi256)
