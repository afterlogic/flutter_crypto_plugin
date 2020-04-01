//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/rsa/X931SignatureSpi.java
//

#include "AsymmetricBlockCipher.h"
#include "CipherParameters.h"
#include "Digest.h"
#include "DigestFactory.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "RIPEMD128Digest.h"
#include "RIPEMD160Digest.h"
#include "RSABlindedEngine.h"
#include "RSAKeyParameters.h"
#include "RSAUtil.h"
#include "WhirlpoolDigest.h"
#include "X931SignatureSpi.h"
#include "X931Signer.h"
#include "java/lang/Exception.h"
#include "java/lang/UnsupportedOperationException.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"
#include "java/security/SignatureException.h"
#include "java/security/SignatureSpi.h"
#include "java/security/interfaces/RSAPrivateKey.h"
#include "java/security/interfaces/RSAPublicKey.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi () {
 @public
  LibOrgBouncycastleCryptoSignersX931Signer *signer_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi, signer_, LibOrgBouncycastleCryptoSignersX931Signer *)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi

- (instancetype)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
     withLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)cipher {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(self, digest, cipher);
  return self;
}

- (void)engineInitVerifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)publicKey {
  id<LibOrgBouncycastleCryptoCipherParameters> param = LibOrgBouncycastleJcajceProviderAsymmetricRsaRSAUtil_generatePublicKeyParameterWithJavaSecurityInterfacesRSAPublicKey_((id<JavaSecurityInterfacesRSAPublicKey>) cast_check(publicKey, JavaSecurityInterfacesRSAPublicKey_class_()));
  [((LibOrgBouncycastleCryptoSignersX931Signer *) nil_chk(signer_)) init__WithBoolean:false withLibOrgBouncycastleCryptoCipherParameters:param];
}

- (void)engineInitSignWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privateKey {
  id<LibOrgBouncycastleCryptoCipherParameters> param = LibOrgBouncycastleJcajceProviderAsymmetricRsaRSAUtil_generatePrivateKeyParameterWithJavaSecurityInterfacesRSAPrivateKey_((id<JavaSecurityInterfacesRSAPrivateKey>) cast_check(privateKey, JavaSecurityInterfacesRSAPrivateKey_class_()));
  [((LibOrgBouncycastleCryptoSignersX931Signer *) nil_chk(signer_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:param];
}

- (void)engineUpdateWithByte:(jbyte)b {
  [((LibOrgBouncycastleCryptoSignersX931Signer *) nil_chk(signer_)) updateWithByte:b];
}

- (void)engineUpdateWithByteArray:(IOSByteArray *)b
                          withInt:(jint)off
                          withInt:(jint)len {
  [((LibOrgBouncycastleCryptoSignersX931Signer *) nil_chk(signer_)) updateWithByteArray:b withInt:off withInt:len];
}

- (IOSByteArray *)engineSign {
  @try {
    IOSByteArray *sig = [((LibOrgBouncycastleCryptoSignersX931Signer *) nil_chk(signer_)) generateSignature];
    return sig;
  }
  @catch (JavaLangException *e) {
    @throw new_JavaSecuritySignatureException_initWithNSString_([e description]);
  }
}

- (jboolean)engineVerifyWithByteArray:(IOSByteArray *)sigBytes {
  jboolean yes = [((LibOrgBouncycastleCryptoSignersX931Signer *) nil_chk(signer_)) verifySignatureWithByteArray:sigBytes];
  return yes;
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

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x4, 4, 5, 3, -1, -1, -1 },
    { NULL, "V", 0x4, 6, 7, 8, -1, -1, -1 },
    { NULL, "V", 0x4, 6, 9, 8, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, 8, -1, -1, -1 },
    { NULL, "Z", 0x4, 10, 11, 8, -1, -1, -1 },
    { NULL, "V", 0x4, 12, 13, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 12, 14, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x4, 15, 16, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoDigest:withLibOrgBouncycastleCryptoAsymmetricBlockCipher:);
  methods[1].selector = @selector(engineInitVerifyWithJavaSecurityPublicKey:);
  methods[2].selector = @selector(engineInitSignWithJavaSecurityPrivateKey:);
  methods[3].selector = @selector(engineUpdateWithByte:);
  methods[4].selector = @selector(engineUpdateWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(engineSign);
  methods[6].selector = @selector(engineVerifyWithByteArray:);
  methods[7].selector = @selector(engineSetParameterWithJavaSecuritySpecAlgorithmParameterSpec:);
  methods[8].selector = @selector(engineSetParameterWithNSString:withId:);
  methods[9].selector = @selector(engineGetParameterWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "signer_", "LLibOrgBouncycastleCryptoSignersX931Signer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigest;LLibOrgBouncycastleCryptoAsymmetricBlockCipher;", "engineInitVerify", "LJavaSecurityPublicKey;", "LJavaSecurityInvalidKeyException;", "engineInitSign", "LJavaSecurityPrivateKey;", "engineUpdate", "B", "LJavaSecuritySignatureException;", "[BII", "engineVerify", "[B", "engineSetParameter", "LJavaSecuritySpecAlgorithmParameterSpec;", "LNSString;LNSObject;", "engineGetParameter", "LNSString;", "LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption;LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption;LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption;LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption;LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption;LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption;LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption;LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption;LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption;LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi = { "X931SignatureSpi", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, fields, 7, 0x1, 10, 1, -1, 17, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi *self, id<LibOrgBouncycastleCryptoDigest> digest, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher) {
  JavaSecuritySignatureSpi_init(self);
  self->signer_ = new_LibOrgBouncycastleCryptoSignersX931Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(cipher, digest);
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(id<LibOrgBouncycastleCryptoDigest> digest, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi, initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_, digest, cipher)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(id<LibOrgBouncycastleCryptoDigest> digest, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi, initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_, digest, cipher)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption = { "RIPEMD128WithRSAEncryption", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(self, new_LibOrgBouncycastleCryptoDigestsRIPEMD128Digest_init(), new_LibOrgBouncycastleCryptoEnginesRSABlindedEngine_init());
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD128WithRSAEncryption)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption = { "RIPEMD160WithRSAEncryption", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(self, new_LibOrgBouncycastleCryptoDigestsRIPEMD160Digest_init(), new_LibOrgBouncycastleCryptoEnginesRSABlindedEngine_init());
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_RIPEMD160WithRSAEncryption)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption = { "SHA1WithRSAEncryption", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(self, LibOrgBouncycastleCryptoUtilDigestFactory_createSHA1(), new_LibOrgBouncycastleCryptoEnginesRSABlindedEngine_init());
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA1WithRSAEncryption)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption = { "SHA224WithRSAEncryption", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(self, LibOrgBouncycastleCryptoUtilDigestFactory_createSHA224(), new_LibOrgBouncycastleCryptoEnginesRSABlindedEngine_init());
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA224WithRSAEncryption)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption = { "SHA256WithRSAEncryption", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(self, LibOrgBouncycastleCryptoUtilDigestFactory_createSHA256(), new_LibOrgBouncycastleCryptoEnginesRSABlindedEngine_init());
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA256WithRSAEncryption)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption = { "SHA384WithRSAEncryption", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(self, LibOrgBouncycastleCryptoUtilDigestFactory_createSHA384(), new_LibOrgBouncycastleCryptoEnginesRSABlindedEngine_init());
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA384WithRSAEncryption)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption = { "SHA512WithRSAEncryption", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(self, LibOrgBouncycastleCryptoUtilDigestFactory_createSHA512(), new_LibOrgBouncycastleCryptoEnginesRSABlindedEngine_init());
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512WithRSAEncryption)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption = { "SHA512_224WithRSAEncryption", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(self, LibOrgBouncycastleCryptoUtilDigestFactory_createSHA512_224(), new_LibOrgBouncycastleCryptoEnginesRSABlindedEngine_init());
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_224WithRSAEncryption)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption = { "SHA512_256WithRSAEncryption", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(self, LibOrgBouncycastleCryptoUtilDigestFactory_createSHA512_256(), new_LibOrgBouncycastleCryptoEnginesRSABlindedEngine_init());
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_SHA512_256WithRSAEncryption)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption = { "WhirlpoolWithRSAEncryption", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(self, new_LibOrgBouncycastleCryptoDigestsWhirlpoolDigest_init(), new_LibOrgBouncycastleCryptoEnginesRSABlindedEngine_init());
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaX931SignatureSpi_WhirlpoolWithRSAEncryption)