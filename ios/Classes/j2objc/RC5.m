//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/RC5.java
//

#include "AlgorithmProvider.h"
#include "BaseAlgorithmParameterGenerator.h"
#include "BaseBlockCipher.h"
#include "BaseKeyGenerator.h"
#include "BaseMac.h"
#include "CBCBlockCipher.h"
#include "CBCBlockCipherMac.h"
#include "CFBBlockCipherMac.h"
#include "CipherKeyGenerator.h"
#include "ConfigurableProvider.h"
#include "CryptoServicesRegistrar.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "IvAlgorithmParameters.h"
#include "J2ObjC_source.h"
#include "RC5.h"
#include "RC532Engine.h"
#include "RC564Engine.h"
#include "java/lang/Exception.h"
#include "java/lang/RuntimeException.h"
#include "java/security/AlgorithmParameters.h"
#include "java/security/InvalidAlgorithmParameterException.h"
#include "java/security/SecureRandom.h"
#include "java/security/spec/AlgorithmParameterSpec.h"
#include "javax/crypto/spec/IvParameterSpec.h"

@interface LibOrgBouncycastleJcajceProviderSymmetricRC5 ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderSymmetricRC5_init(LibOrgBouncycastleJcajceProviderSymmetricRC5 *self);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricRC5 *new_LibOrgBouncycastleJcajceProviderSymmetricRC5_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricRC5 *create_LibOrgBouncycastleJcajceProviderSymmetricRC5_init(void);

inline NSString *LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings, PREFIX, NSString *)

@implementation LibOrgBouncycastleJcajceProviderSymmetricRC5

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricRC5_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32;LLibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64;LLibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32;LLibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32;LLibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64;LLibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen;LLibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32;LLibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32;LLibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams;LLibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricRC5 = { "RC5", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x11, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricRC5;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricRC5_init(LibOrgBouncycastleJcajceProviderSymmetricRC5 *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricRC5 *new_LibOrgBouncycastleJcajceProviderSymmetricRC5_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5, init)
}

LibOrgBouncycastleJcajceProviderSymmetricRC5 *create_LibOrgBouncycastleJcajceProviderSymmetricRC5_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricRC5)

@implementation LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricRC5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32 = { "ECB32", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32_init(LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, new_LibOrgBouncycastleCryptoEnginesRC532Engine_init());
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32 *new_LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32, init)
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32 *create_LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB32)

@implementation LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricRC5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64 = { "ECB64", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64_init(LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, new_LibOrgBouncycastleCryptoEnginesRC564Engine_init());
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64 *new_LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64, init)
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64 *create_LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricRC5_ECB64)

@implementation LibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricRC5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32 = { "CBC32", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32_init(LibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_(self, new_LibOrgBouncycastleCryptoModesCBCBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(new_LibOrgBouncycastleCryptoEnginesRC532Engine_init()), 64);
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32 *new_LibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32, init)
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32 *create_LibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricRC5_CBC32)

@implementation LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricRC5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32 = { "KeyGen32", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32_init(LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"RC5", 128, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32 *new_LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32, init)
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32 *create_LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen32)

@implementation LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricRC5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64 = { "KeyGen64", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64_init(LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"RC5-64", 256, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64 *new_LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64, init)
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64 *create_LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricRC5_KeyGen64)

@implementation LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)genParamSpec
                                withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_(@"No supported AlgorithmParameterSpec for RC5 parameter generation.");
}

- (JavaSecurityAlgorithmParameters *)engineGenerateParameters {
  IOSByteArray *iv = [IOSByteArray newArrayWithLength:8];
  if (random_ == nil) {
    random_ = LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom();
  }
  [((JavaSecuritySecureRandom *) nil_chk(random_)) nextBytesWithByteArray:iv];
  JavaSecurityAlgorithmParameters *params;
  @try {
    params = [self createParametersInstanceWithNSString:@"RC5"];
    [((JavaSecurityAlgorithmParameters *) nil_chk(params)) init__WithJavaSecuritySpecAlgorithmParameterSpec:new_JavaxCryptoSpecIvParameterSpec_initWithByteArray_(iv)];
  }
  @catch (JavaLangException *e) {
    @throw new_JavaLangRuntimeException_initWithNSString_([e getMessage]);
  }
  return params;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 0, 1, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityAlgorithmParameters;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineInitWithJavaSecuritySpecAlgorithmParameterSpec:withJavaSecuritySecureRandom:);
  methods[2].selector = @selector(engineGenerateParameters);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "engineInit", "LJavaSecuritySpecAlgorithmParameterSpec;LJavaSecuritySecureRandom;", "LJavaSecurityInvalidAlgorithmParameterException;", "LLibOrgBouncycastleJcajceProviderSymmetricRC5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen = { "AlgParamGen", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 3, 0, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen_init(LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen *new_LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen, init)
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen *create_LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParamGen)

@implementation LibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricRC5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32 = { "Mac32", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32_init(LibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac_initWithLibOrgBouncycastleCryptoMac_(self, new_LibOrgBouncycastleCryptoMacsCBCBlockCipherMac_initWithLibOrgBouncycastleCryptoBlockCipher_(new_LibOrgBouncycastleCryptoEnginesRC532Engine_init()));
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32 *new_LibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32, init)
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32 *create_LibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricRC5_Mac32)

@implementation LibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricRC5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32 = { "CFB8Mac32", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32_init(LibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac_initWithLibOrgBouncycastleCryptoMac_(self, new_LibOrgBouncycastleCryptoMacsCFBBlockCipherMac_initWithLibOrgBouncycastleCryptoBlockCipher_(new_LibOrgBouncycastleCryptoEnginesRC532Engine_init()));
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32 *new_LibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32, init)
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32 *create_LibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricRC5_CFB8Mac32)

@implementation LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (NSString *)engineToString {
  return @"RC5 IV";
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineToString);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricRC5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams = { "AlgParams", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 2, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams_init(LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilIvAlgorithmParameters_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams *new_LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams, init)
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams *create_LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricRC5_AlgParams)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings)

@implementation LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"Cipher.RC5" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_PREFIX, @"$ECB32")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Cipher.RC5-32" withNSString:@"RC5"];
  [provider addAlgorithmWithNSString:@"Cipher.RC5-64" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_PREFIX, @"$ECB64")];
  [provider addAlgorithmWithNSString:@"KeyGenerator.RC5" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_PREFIX, @"$KeyGen32")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyGenerator.RC5-32" withNSString:@"RC5"];
  [provider addAlgorithmWithNSString:@"KeyGenerator.RC5-64" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_PREFIX, @"$KeyGen64")];
  [provider addAlgorithmWithNSString:@"AlgorithmParameters.RC5" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_PREFIX, @"$AlgParams")];
  [provider addAlgorithmWithNSString:@"AlgorithmParameters.RC5-64" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_PREFIX, @"$AlgParams")];
  [provider addAlgorithmWithNSString:@"Mac.RC5MAC" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_PREFIX, @"$Mac32")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Mac.RC5" withNSString:@"RC5MAC"];
  [provider addAlgorithmWithNSString:@"Mac.RC5MAC/CFB8" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_PREFIX, @"$CFB8Mac32")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Mac.RC5/CFB8" withNSString:@"RC5MAC/CFB8"];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "PREFIX", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 2, -1, -1 },
  };
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", &LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_PREFIX, "LLibOrgBouncycastleJcajceProviderSymmetricRC5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings class]) {
    LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_PREFIX = [LibOrgBouncycastleJcajceProviderSymmetricRC5_class_() getName];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings)
  }
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings, init)
}

LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricRC5_Mappings)
