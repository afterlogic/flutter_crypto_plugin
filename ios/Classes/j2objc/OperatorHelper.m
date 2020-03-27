//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/jcajce/OperatorHelper.java
//

#include "HashAlgorithmTags.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcaJceHelper.h"
#include "OperatorHelper.h"
#include "PGPDataDecryptor.h"
#include "PGPDigestCalculator.h"
#include "PGPException.h"
#include "PGPUtil.h"
#include "PublicKeyAlgorithmTags.h"
#include "SHA1PGPDigestCalculator.h"
#include "SymmetricKeyAlgorithmTags.h"
#include "java/io/InputStream.h"
#include "java/lang/Exception.h"
#include "java/security/AlgorithmParameters.h"
#include "java/security/GeneralSecurityException.h"
#include "java/security/KeyFactory.h"
#include "java/security/KeyPairGenerator.h"
#include "java/security/MessageDigest.h"
#include "java/security/NoSuchAlgorithmException.h"
#include "java/security/Signature.h"
#include "javax/crypto/Cipher.h"
#include "javax/crypto/CipherInputStream.h"
#include "javax/crypto/KeyAgreement.h"
#include "javax/crypto/SecretKey.h"
#include "javax/crypto/spec/IvParameterSpec.h"
#include "javax/crypto/spec/SecretKeySpec.h"

@interface LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper () {
 @public
  id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper_;
}

- (JavaSecuritySignature *)createSignatureWithNSString:(NSString *)cipherName;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper, helper_, id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)

__attribute__((unused)) static JavaSecuritySignature *LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_createSignatureWithNSString_(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper *self, NSString *cipherName);

@interface LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1 : NSObject < LibOrgBouncycastleOpenpgpOperatorPGPDataDecryptor > {
 @public
  JavaxCryptoCipher *val$c_;
}

- (instancetype)initWithJavaxCryptoCipher:(JavaxCryptoCipher *)capture$0;

- (JavaIoInputStream *)getInputStreamWithJavaIoInputStream:(JavaIoInputStream *)inArg;

- (jint)getBlockSize;

- (id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)getIntegrityCalculator;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1_initWithJavaxCryptoCipher_(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1 *self, JavaxCryptoCipher *capture$0);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1 *new_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1_initWithJavaxCryptoCipher_(JavaxCryptoCipher *capture$0) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1 *create_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1_initWithJavaxCryptoCipher_(JavaxCryptoCipher *capture$0);

@implementation LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper

- (instancetype)initWithLibOrgBouncycastleJcajceUtilJcaJceHelper:(id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)helper {
  LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(self, helper);
  return self;
}

- (NSString *)getDigestNameWithInt:(jint)hashAlgorithm {
  switch (hashAlgorithm) {
    case LibOrgBouncycastleBcpgHashAlgorithmTags_SHA1:
    return @"SHA-1";
    case LibOrgBouncycastleBcpgHashAlgorithmTags_MD2:
    return @"MD2";
    case LibOrgBouncycastleBcpgHashAlgorithmTags_MD5:
    return @"MD5";
    case LibOrgBouncycastleBcpgHashAlgorithmTags_RIPEMD160:
    return @"RIPEMD160";
    case LibOrgBouncycastleBcpgHashAlgorithmTags_SHA256:
    return @"SHA-256";
    case LibOrgBouncycastleBcpgHashAlgorithmTags_SHA384:
    return @"SHA-384";
    case LibOrgBouncycastleBcpgHashAlgorithmTags_SHA512:
    return @"SHA-512";
    case LibOrgBouncycastleBcpgHashAlgorithmTags_SHA224:
    return @"SHA-224";
    case LibOrgBouncycastleBcpgHashAlgorithmTags_TIGER_192:
    return @"TIGER";
    default:
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(JreStrcat("$I", @"unknown hash algorithm tag in getDigestName: ", hashAlgorithm));
  }
}

- (JavaSecurityMessageDigest *)createDigestWithInt:(jint)algorithm {
  JavaSecurityMessageDigest *dig;
  NSString *digestName = [self getDigestNameWithInt:algorithm];
  @try {
    dig = [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(helper_)) createDigestWithNSString:digestName];
  }
  @catch (JavaSecurityNoSuchAlgorithmException *e) {
    if (algorithm >= LibOrgBouncycastleBcpgHashAlgorithmTags_SHA256 && algorithm <= LibOrgBouncycastleBcpgHashAlgorithmTags_SHA224) {
      dig = [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(helper_)) createDigestWithNSString:JreStrcat("$$", @"SHA", [((NSString *) nil_chk(digestName)) java_substring:4])];
    }
    else {
      @throw e;
    }
  }
  return dig;
}

- (JavaSecurityKeyFactory *)createKeyFactoryWithNSString:(NSString *)algorithm {
  return [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(helper_)) createKeyFactoryWithNSString:algorithm];
}

- (JavaxCryptoKeyAgreement *)createKeyAgreementWithNSString:(NSString *)algorithm {
  return [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(helper_)) createKeyAgreementWithNSString:algorithm];
}

- (JavaSecurityKeyPairGenerator *)createKeyPairGeneratorWithNSString:(NSString *)algorithm {
  return [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(helper_)) createKeyPairGeneratorWithNSString:algorithm];
}

- (id<LibOrgBouncycastleOpenpgpOperatorPGPDataDecryptor>)createDataDecryptorWithBoolean:(jboolean)withIntegrityPacket
                                                                                withInt:(jint)encAlgorithm
                                                                          withByteArray:(IOSByteArray *)key {
  @try {
    id<JavaxCryptoSecretKey> secretKey = new_JavaxCryptoSpecSecretKeySpec_initWithByteArray_withNSString_(key, LibOrgBouncycastleOpenpgpPGPUtil_getSymmetricCipherNameWithInt_(encAlgorithm));
    JavaxCryptoCipher *c = [self createStreamCipherWithInt:encAlgorithm withBoolean:withIntegrityPacket];
    if (withIntegrityPacket) {
      IOSByteArray *iv = [IOSByteArray newArrayWithLength:[((JavaxCryptoCipher *) nil_chk(c)) getBlockSize]];
      [c init__WithInt:JavaxCryptoCipher_DECRYPT_MODE withJavaSecurityKey:secretKey withJavaSecuritySpecAlgorithmParameterSpec:new_JavaxCryptoSpecIvParameterSpec_initWithByteArray_(iv)];
    }
    else {
      [((JavaxCryptoCipher *) nil_chk(c)) init__WithInt:JavaxCryptoCipher_DECRYPT_MODE withJavaSecurityKey:secretKey];
    }
    return new_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1_initWithJavaxCryptoCipher_(c);
  }
  @catch (LibOrgBouncycastleOpenpgpPGPException *e) {
    @throw e;
  }
  @catch (JavaLangException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(@"Exception creating cipher", e);
  }
}

- (JavaxCryptoCipher *)createStreamCipherWithInt:(jint)encAlgorithm
                                     withBoolean:(jboolean)withIntegrityPacket {
  NSString *mode = (withIntegrityPacket) ? @"CFB" : @"OpenPGPCFB";
  NSString *cName = JreStrcat("$C$$", LibOrgBouncycastleOpenpgpPGPUtil_getSymmetricCipherNameWithInt_(encAlgorithm), '/', mode, @"/NoPadding");
  return [self createCipherWithNSString:cName];
}

- (JavaxCryptoCipher *)createCipherWithNSString:(NSString *)cipherName {
  @try {
    return [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(helper_)) createCipherWithNSString:cipherName];
  }
  @catch (JavaSecurityGeneralSecurityException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(JreStrcat("$$", @"cannot create cipher: ", [e getMessage]), e);
  }
}

- (JavaxCryptoCipher *)createPublicKeyCipherWithInt:(jint)encAlgorithm {
  switch (encAlgorithm) {
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_ENCRYPT:
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_GENERAL:
    return [self createCipherWithNSString:@"RSA/ECB/PKCS1Padding"];
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_ENCRYPT:
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_GENERAL:
    return [self createCipherWithNSString:@"ElGamal/ECB/PKCS1Padding"];
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_DSA:
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"Can't use DSA for encryption.");
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDSA:
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"Can't use ECDSA for encryption.");
    default:
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(JreStrcat("$I", @"unknown asymmetric algorithm: ", encAlgorithm));
  }
}

- (JavaxCryptoCipher *)createKeyWrapperWithInt:(jint)encAlgorithm {
  @try {
    switch (encAlgorithm) {
      case LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags_AES_128:
      case LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags_AES_192:
      case LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags_AES_256:
      return [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(helper_)) createCipherWithNSString:@"AESWrap"];
      case LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags_CAMELLIA_128:
      case LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags_CAMELLIA_192:
      case LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags_CAMELLIA_256:
      return [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(helper_)) createCipherWithNSString:@"CamelliaWrap"];
      default:
      @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(JreStrcat("$I", @"unknown wrap algorithm: ", encAlgorithm));
    }
  }
  @catch (JavaSecurityGeneralSecurityException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(JreStrcat("$$", @"cannot create cipher: ", [e getMessage]), e);
  }
}

- (JavaSecuritySignature *)createSignatureWithNSString:(NSString *)cipherName {
  return LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_createSignatureWithNSString_(self, cipherName);
}

- (JavaSecuritySignature *)createSignatureWithInt:(jint)keyAlgorithm
                                          withInt:(jint)hashAlgorithm {
  NSString *encAlg;
  switch (keyAlgorithm) {
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_GENERAL:
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_SIGN:
    encAlg = @"RSA";
    break;
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_DSA:
    encAlg = @"DSA";
    break;
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_ENCRYPT:
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_GENERAL:
    encAlg = @"ElGamal";
    break;
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDSA:
    encAlg = @"ECDSA";
    break;
    default:
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(JreStrcat("$I", @"unknown algorithm tag in signature:", keyAlgorithm));
  }
  return LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_createSignatureWithNSString_(self, JreStrcat("$$$", LibOrgBouncycastleOpenpgpPGPUtil_getDigestNameWithInt_(hashAlgorithm), @"with", encAlg));
}

- (JavaSecurityAlgorithmParameters *)createAlgorithmParametersWithNSString:(NSString *)algorithm {
  return [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(helper_)) createAlgorithmParametersWithNSString:algorithm];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x0, 1, 2, 3, -1, -1, -1 },
    { NULL, "LJavaSecurityMessageDigest;", 0x0, 4, 2, 5, -1, -1, -1 },
    { NULL, "LJavaSecurityKeyFactory;", 0x0, 6, 7, 5, -1, -1, -1 },
    { NULL, "LJavaxCryptoKeyAgreement;", 0x1, 8, 7, 9, -1, -1, -1 },
    { NULL, "LJavaSecurityKeyPairGenerator;", 0x1, 10, 7, 9, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorPGPDataDecryptor;", 0x0, 11, 12, 3, -1, -1, -1 },
    { NULL, "LJavaxCryptoCipher;", 0x0, 13, 14, 3, -1, -1, -1 },
    { NULL, "LJavaxCryptoCipher;", 0x0, 15, 7, 3, -1, -1, -1 },
    { NULL, "LJavaxCryptoCipher;", 0x0, 16, 2, 3, -1, -1, -1 },
    { NULL, "LJavaxCryptoCipher;", 0x0, 17, 2, 3, -1, -1, -1 },
    { NULL, "LJavaSecuritySignature;", 0x2, 18, 7, 3, -1, -1, -1 },
    { NULL, "LJavaSecuritySignature;", 0x1, 18, 19, 3, -1, -1, -1 },
    { NULL, "LJavaSecurityAlgorithmParameters;", 0x1, 20, 7, 21, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleJcajceUtilJcaJceHelper:);
  methods[1].selector = @selector(getDigestNameWithInt:);
  methods[2].selector = @selector(createDigestWithInt:);
  methods[3].selector = @selector(createKeyFactoryWithNSString:);
  methods[4].selector = @selector(createKeyAgreementWithNSString:);
  methods[5].selector = @selector(createKeyPairGeneratorWithNSString:);
  methods[6].selector = @selector(createDataDecryptorWithBoolean:withInt:withByteArray:);
  methods[7].selector = @selector(createStreamCipherWithInt:withBoolean:);
  methods[8].selector = @selector(createCipherWithNSString:);
  methods[9].selector = @selector(createPublicKeyCipherWithInt:);
  methods[10].selector = @selector(createKeyWrapperWithInt:);
  methods[11].selector = @selector(createSignatureWithNSString:);
  methods[12].selector = @selector(createSignatureWithInt:withInt:);
  methods[13].selector = @selector(createAlgorithmParametersWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "helper_", "LLibOrgBouncycastleJcajceUtilJcaJceHelper;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceUtilJcaJceHelper;", "getDigestName", "I", "LLibOrgBouncycastleOpenpgpPGPException;", "createDigest", "LJavaSecurityGeneralSecurityException;LLibOrgBouncycastleOpenpgpPGPException;", "createKeyFactory", "LNSString;", "createKeyAgreement", "LJavaSecurityGeneralSecurityException;", "createKeyPairGenerator", "createDataDecryptor", "ZI[B", "createStreamCipher", "IZ", "createCipher", "createPublicKeyCipher", "createKeyWrapper", "createSignature", "II", "createAlgorithmParameters", "LJavaSecurityNoSuchProviderException;LJavaSecurityNoSuchAlgorithmException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper = { "OperatorHelper", "lib.org.bouncycastle.openpgp.operator.jcajce", ptrTable, methods, fields, 7, 0x0, 14, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper;
}

@end

void LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper *self, id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper) {
  NSObject_init(self);
  self->helper_ = helper;
}

LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper *new_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper, initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_, helper)
}

LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper *create_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper, initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_, helper)
}

JavaSecuritySignature *LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_createSignatureWithNSString_(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper *self, NSString *cipherName) {
  @try {
    return [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(self->helper_)) createSignatureWithNSString:cipherName];
  }
  @catch (JavaSecurityGeneralSecurityException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(JreStrcat("$$", @"cannot create signature: ", [e getMessage]), e);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper)

@implementation LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1

- (instancetype)initWithJavaxCryptoCipher:(JavaxCryptoCipher *)capture$0 {
  LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1_initWithJavaxCryptoCipher_(self, capture$0);
  return self;
}

- (JavaIoInputStream *)getInputStreamWithJavaIoInputStream:(JavaIoInputStream *)inArg {
  return new_JavaxCryptoCipherInputStream_initWithJavaIoInputStream_withJavaxCryptoCipher_(inArg, val$c_);
}

- (jint)getBlockSize {
  return [((JavaxCryptoCipher *) nil_chk(val$c_)) getBlockSize];
}

- (id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)getIntegrityCalculator {
  return new_LibOrgBouncycastleOpenpgpOperatorJcajceSHA1PGPDigestCalculator_init();
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaIoInputStream;", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaxCryptoCipher:);
  methods[1].selector = @selector(getInputStreamWithJavaIoInputStream:);
  methods[2].selector = @selector(getBlockSize);
  methods[3].selector = @selector(getIntegrityCalculator);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "val$c_", "LJavaxCryptoCipher;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInputStream", "LJavaIoInputStream;", "LLibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper;", "createDataDecryptorWithBoolean:withInt:withByteArray:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1 = { "", "lib.org.bouncycastle.openpgp.operator.jcajce", ptrTable, methods, fields, 7, 0x8010, 4, 1, 2, -1, 3, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1;
}

@end

void LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1_initWithJavaxCryptoCipher_(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1 *self, JavaxCryptoCipher *capture$0) {
  self->val$c_ = capture$0;
  NSObject_init(self);
}

LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1 *new_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1_initWithJavaxCryptoCipher_(JavaxCryptoCipher *capture$0) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1, initWithJavaxCryptoCipher_, capture$0)
}

LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1 *create_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1_initWithJavaxCryptoCipher_(JavaxCryptoCipher *capture$0) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_1, initWithJavaxCryptoCipher_, capture$0)
}