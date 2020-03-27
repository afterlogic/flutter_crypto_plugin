//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/bc/BcPBESecretKeyEncryptorBuilder.java
//

#include "BcImplProvider.h"
#include "BcPBESecretKeyEncryptorBuilder.h"
#include "BcUtil.h"
#include "BlockCipher.h"
#include "BufferedBlockCipher.h"
#include "IOSPrimitiveArray.h"
#include "InvalidCipherTextException.h"
#include "J2ObjC_source.h"
#include "OpenPgpBcSHA1PGPDigestCalculator.h"
#include "PBESecretKeyEncryptor.h"
#include "PGPDigestCalculator.h"
#include "PGPException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder () {
 @public
  jint encAlgorithm_;
  id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator_;
  JavaSecuritySecureRandom *random_;
  jint s2kCount_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder, s2kDigestCalculator_, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder, random_, JavaSecuritySecureRandom *)

@interface LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1 : LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor {
 @public
  IOSByteArray *iv_;
}

- (instancetype)initWithInt:(jint)encAlgorithm
withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)s2kDigestCalculator
                    withInt:(jint)s2kCount
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
              withCharArray:(IOSCharArray *)passPhrase;

- (IOSByteArray *)encryptKeyDataWithByteArray:(IOSByteArray *)key
                                withByteArray:(IOSByteArray *)keyData
                                      withInt:(jint)keyOff
                                      withInt:(jint)keyLen;

- (IOSByteArray *)encryptKeyDataWithByteArray:(IOSByteArray *)key
                                withByteArray:(IOSByteArray *)iv
                                withByteArray:(IOSByteArray *)keyData
                                      withInt:(jint)keyOff
                                      withInt:(jint)keyLen;

- (IOSByteArray *)getCipherIV;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1, iv_, IOSByteArray *)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_withJavaSecuritySecureRandom_withCharArray_(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1 *self, jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, jint s2kCount, JavaSecuritySecureRandom *random, IOSCharArray *passPhrase);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1 *new_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_withJavaSecuritySecureRandom_withCharArray_(jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, jint s2kCount, JavaSecuritySecureRandom *random, IOSCharArray *passPhrase) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1 *create_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_withJavaSecuritySecureRandom_withCharArray_(jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, jint s2kCount, JavaSecuritySecureRandom *random, IOSCharArray *passPhrase);

@implementation LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder

- (instancetype)initWithInt:(jint)encAlgorithm {
  LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_(self, encAlgorithm);
  return self;
}

- (instancetype)initWithInt:(jint)encAlgorithm
                    withInt:(jint)s2kCount {
  LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withInt_(self, encAlgorithm, s2kCount);
  return self;
}

- (instancetype)initWithInt:(jint)encAlgorithm
withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)s2kDigestCalculator {
  LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_(self, encAlgorithm, s2kDigestCalculator);
  return self;
}

- (instancetype)initWithInt:(jint)encAlgorithm
withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)s2kDigestCalculator
                    withInt:(jint)s2kCount {
  LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_(self, encAlgorithm, s2kDigestCalculator, s2kCount);
  return self;
}

- (LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder *)setSecureRandomWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  self->random_ = random;
  return self;
}

- (LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *)buildWithCharArray:(IOSCharArray *)passPhrase {
  if (self->random_ == nil) {
    self->random_ = new_JavaSecuritySecureRandom_init();
  }
  return new_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_withJavaSecuritySecureRandom_withCharArray_(encAlgorithm_, s2kDigestCalculator_, s2kCount_, self->random_, passPhrase);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder;", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor;", 0x1, 6, 7, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:);
  methods[1].selector = @selector(initWithInt:withInt:);
  methods[2].selector = @selector(initWithInt:withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:);
  methods[3].selector = @selector(initWithInt:withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:withInt:);
  methods[4].selector = @selector(setSecureRandomWithJavaSecuritySecureRandom:);
  methods[5].selector = @selector(buildWithCharArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "encAlgorithm_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "s2kDigestCalculator_", "LLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "s2kCount_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I", "II", "ILLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator;", "ILLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator;I", "setSecureRandom", "LJavaSecuritySecureRandom;", "build", "[C" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder = { "BcPBESecretKeyEncryptorBuilder", "lib.org.bouncycastle.openpgp.operator.bc", ptrTable, methods, fields, 7, 0x1, 6, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder;
}

@end

void LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder *self, jint encAlgorithm) {
  LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_(self, encAlgorithm, new_LibOrgBouncycastleOpenpgpOperatorBcOpenPgpBcSHA1PGPDigestCalculator_init());
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder *new_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_(jint encAlgorithm) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder, initWithInt_, encAlgorithm)
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder *create_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_(jint encAlgorithm) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder, initWithInt_, encAlgorithm)
}

void LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withInt_(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder *self, jint encAlgorithm, jint s2kCount) {
  LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_(self, encAlgorithm, new_LibOrgBouncycastleOpenpgpOperatorBcOpenPgpBcSHA1PGPDigestCalculator_init(), s2kCount);
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder *new_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withInt_(jint encAlgorithm, jint s2kCount) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder, initWithInt_withInt_, encAlgorithm, s2kCount)
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder *create_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withInt_(jint encAlgorithm, jint s2kCount) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder, initWithInt_withInt_, encAlgorithm, s2kCount)
}

void LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder *self, jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator) {
  LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_(self, encAlgorithm, s2kDigestCalculator, (jint) 0x60);
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder *new_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_(jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder, initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_, encAlgorithm, s2kDigestCalculator)
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder *create_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_(jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder, initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_, encAlgorithm, s2kDigestCalculator)
}

void LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder *self, jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, jint s2kCount) {
  NSObject_init(self);
  self->s2kCount_ = (jint) 0x60;
  self->encAlgorithm_ = encAlgorithm;
  self->s2kDigestCalculator_ = s2kDigestCalculator;
  if (s2kCount < 0 || s2kCount > (jint) 0xff) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"s2KCount value outside of range 0 to 255.");
  }
  self->s2kCount_ = s2kCount;
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder *new_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_(jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, jint s2kCount) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder, initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_, encAlgorithm, s2kDigestCalculator, s2kCount)
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder *create_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_(jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, jint s2kCount) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder, initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_, encAlgorithm, s2kDigestCalculator, s2kCount)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder)

@implementation LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1

- (instancetype)initWithInt:(jint)encAlgorithm
withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)s2kDigestCalculator
                    withInt:(jint)s2kCount
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
              withCharArray:(IOSCharArray *)passPhrase {
  LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_withJavaSecuritySecureRandom_withCharArray_(self, encAlgorithm, s2kDigestCalculator, s2kCount, random, passPhrase);
  return self;
}

- (IOSByteArray *)encryptKeyDataWithByteArray:(IOSByteArray *)key
                                withByteArray:(IOSByteArray *)keyData
                                      withInt:(jint)keyOff
                                      withInt:(jint)keyLen {
  return [self encryptKeyDataWithByteArray:key withByteArray:nil withByteArray:keyData withInt:keyOff withInt:keyLen];
}

- (IOSByteArray *)encryptKeyDataWithByteArray:(IOSByteArray *)key
                                withByteArray:(IOSByteArray *)iv
                                withByteArray:(IOSByteArray *)keyData
                                      withInt:(jint)keyOff
                                      withInt:(jint)keyLen {
  @try {
    id<LibOrgBouncycastleCryptoBlockCipher> engine = LibOrgBouncycastleOpenpgpOperatorBcBcImplProvider_createBlockCipherWithInt_(self->encAlgorithm_);
    if (iv != nil) {
      self->iv_ = iv;
    }
    else {
      if (self->random_ == nil) {
        self->random_ = new_JavaSecuritySecureRandom_init();
      }
      self->iv_ = iv = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine)) getBlockSize]];
      [((JavaSecuritySecureRandom *) nil_chk(self->random_)) nextBytesWithByteArray:iv];
    }
    LibOrgBouncycastleCryptoBufferedBlockCipher *c = LibOrgBouncycastleOpenpgpOperatorBcBcUtil_createSymmetricKeyWrapperWithBoolean_withLibOrgBouncycastleCryptoBlockCipher_withByteArray_withByteArray_(true, engine, key, iv);
    IOSByteArray *out = [IOSByteArray newArrayWithLength:keyLen];
    jint outLen = [((LibOrgBouncycastleCryptoBufferedBlockCipher *) nil_chk(c)) processBytesWithByteArray:keyData withInt:keyOff withInt:keyLen withByteArray:out withInt:0];
    outLen += [c doFinalWithByteArray:out withInt:outLen];
    return out;
  }
  @catch (LibOrgBouncycastleCryptoInvalidCipherTextException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(JreStrcat("$$", @"decryption failed: ", [e getMessage]), e);
  }
}

- (IOSByteArray *)getCipherIV {
  return iv_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "[B", 0x1, 1, 4, 3, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:withInt:withJavaSecuritySecureRandom:withCharArray:);
  methods[1].selector = @selector(encryptKeyDataWithByteArray:withByteArray:withInt:withInt:);
  methods[2].selector = @selector(encryptKeyDataWithByteArray:withByteArray:withByteArray:withInt:withInt:);
  methods[3].selector = @selector(getCipherIV);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "iv_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator;ILJavaSecuritySecureRandom;[C", "encryptKeyData", "[B[BII", "LLibOrgBouncycastleOpenpgpPGPException;", "[B[B[BII", "LLibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder;", "buildWithCharArray:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1 = { "", "lib.org.bouncycastle.openpgp.operator.bc", ptrTable, methods, fields, 7, 0x8010, 4, 1, 5, -1, 6, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1;
}

@end

void LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_withJavaSecuritySecureRandom_withCharArray_(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1 *self, jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, jint s2kCount, JavaSecuritySecureRandom *random, IOSCharArray *passPhrase) {
  LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_withJavaSecuritySecureRandom_withCharArray_(self, encAlgorithm, s2kDigestCalculator, s2kCount, random, passPhrase);
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1 *new_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_withJavaSecuritySecureRandom_withCharArray_(jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, jint s2kCount, JavaSecuritySecureRandom *random, IOSCharArray *passPhrase) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1, initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_withJavaSecuritySecureRandom_withCharArray_, encAlgorithm, s2kDigestCalculator, s2kCount, random, passPhrase)
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1 *create_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_withJavaSecuritySecureRandom_withCharArray_(jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, jint s2kCount, JavaSecuritySecureRandom *random, IOSCharArray *passPhrase) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyEncryptorBuilder_1, initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_withJavaSecuritySecureRandom_withCharArray_, encAlgorithm, s2kDigestCalculator, s2kCount, random, passPhrase)
}
