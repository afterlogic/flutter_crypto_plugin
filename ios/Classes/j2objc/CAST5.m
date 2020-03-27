//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/CAST5.java
//

#include "ASN1InputStream.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "AlgorithmProvider.h"
#include "BaseAlgorithmParameterGenerator.h"
#include "BaseAlgorithmParameters.h"
#include "BaseBlockCipher.h"
#include "BaseKeyGenerator.h"
#include "CAST5.h"
#include "CAST5CBCParameters.h"
#include "CAST5Engine.h"
#include "CBCBlockCipher.h"
#include "CipherKeyGenerator.h"
#include "ConfigurableProvider.h"
#include "CryptoServicesRegistrar.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "MiscObjectIdentifiers.h"
#include "java/io/IOException.h"
#include "java/lang/Exception.h"
#include "java/lang/RuntimeException.h"
#include "java/lang/System.h"
#include "java/security/AlgorithmParameters.h"
#include "java/security/InvalidAlgorithmParameterException.h"
#include "java/security/SecureRandom.h"
#include "java/security/spec/AlgorithmParameterSpec.h"
#include "java/security/spec/InvalidParameterSpecException.h"
#include "javax/crypto/spec/IvParameterSpec.h"

@interface LibOrgBouncycastleJcajceProviderSymmetricCAST5 ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderSymmetricCAST5_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5 *self);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricCAST5 *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricCAST5 *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_init(void);

@interface LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams () {
 @public
  IOSByteArray *iv_;
  jint keyLength_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams, iv_, IOSByteArray *)

inline NSString *LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings, PREFIX, NSString *)

@implementation LibOrgBouncycastleJcajceProviderSymmetricCAST5

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricCAST5_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB;LLibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC;LLibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen;LLibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen;LLibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams;LLibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricCAST5 = { "CAST5", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x11, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricCAST5;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricCAST5_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5 *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5 *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5, init)
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5 *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricCAST5)

@implementation LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricCAST5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB = { "ECB", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, new_LibOrgBouncycastleCryptoEnginesCAST5Engine_init());
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB, init)
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB)

@implementation LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricCAST5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC = { "CBC", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_(self, new_LibOrgBouncycastleCryptoModesCBCBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(new_LibOrgBouncycastleCryptoEnginesCAST5Engine_init()), 64);
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC, init)
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC)

@implementation LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricCAST5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen = { "KeyGen", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"CAST5", 128, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen, init)
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen)

@implementation LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)genParamSpec
                                withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_(@"No supported AlgorithmParameterSpec for CAST5 parameter generation.");
}

- (JavaSecurityAlgorithmParameters *)engineGenerateParameters {
  IOSByteArray *iv = [IOSByteArray newArrayWithLength:8];
  if (random_ == nil) {
    random_ = LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom();
  }
  [((JavaSecuritySecureRandom *) nil_chk(random_)) nextBytesWithByteArray:iv];
  JavaSecurityAlgorithmParameters *params;
  @try {
    params = [self createParametersInstanceWithNSString:@"CAST5"];
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
  static const void *ptrTable[] = { "engineInit", "LJavaSecuritySpecAlgorithmParameterSpec;LJavaSecuritySecureRandom;", "LJavaSecurityInvalidAlgorithmParameterException;", "LLibOrgBouncycastleJcajceProviderSymmetricCAST5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen = { "AlgParamGen", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 3, 0, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen, init)
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen)

@implementation LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)engineGetEncoded {
  IOSByteArray *tmp = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(iv_))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(iv_, 0, tmp, 0, iv_->size_);
  return tmp;
}

- (IOSByteArray *)engineGetEncodedWithNSString:(NSString *)format {
  if ([self isASN1FormatStringWithNSString:format]) {
    return [new_LibOrgBouncycastleAsn1MiscCAST5CBCParameters_initWithByteArray_withInt_([self engineGetEncoded], keyLength_) getEncoded];
  }
  if ([((NSString *) nil_chk(format)) isEqual:@"RAW"]) {
    return [self engineGetEncoded];
  }
  return nil;
}

- (id<JavaSecuritySpecAlgorithmParameterSpec>)localEngineGetParameterSpecWithIOSClass:(IOSClass *)paramSpec {
  if (paramSpec == JavaxCryptoSpecIvParameterSpec_class_()) {
    return new_JavaxCryptoSpecIvParameterSpec_initWithByteArray_(iv_);
  }
  @throw new_JavaSecuritySpecInvalidParameterSpecException_initWithNSString_(@"unknown parameter spec passed to CAST5 parameters object.");
}

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)paramSpec {
  if ([paramSpec isKindOfClass:[JavaxCryptoSpecIvParameterSpec class]]) {
    self->iv_ = [((JavaxCryptoSpecIvParameterSpec *) nil_chk(((JavaxCryptoSpecIvParameterSpec *) paramSpec))) getIV];
  }
  else {
    @throw new_JavaSecuritySpecInvalidParameterSpecException_initWithNSString_(@"IvParameterSpec required to initialise a CAST5 parameters algorithm parameters object");
  }
}

- (void)engineInitWithByteArray:(IOSByteArray *)params {
  self->iv_ = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(params))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(params, 0, iv_, 0, iv_->size_);
}

- (void)engineInitWithByteArray:(IOSByteArray *)params
                   withNSString:(NSString *)format {
  if ([self isASN1FormatStringWithNSString:format]) {
    LibOrgBouncycastleAsn1ASN1InputStream *aIn = new_LibOrgBouncycastleAsn1ASN1InputStream_initWithByteArray_(params);
    LibOrgBouncycastleAsn1MiscCAST5CBCParameters *p = LibOrgBouncycastleAsn1MiscCAST5CBCParameters_getInstanceWithId_([aIn readObject]);
    keyLength_ = [((LibOrgBouncycastleAsn1MiscCAST5CBCParameters *) nil_chk(p)) getKeyLength];
    iv_ = [p getIV];
    return;
  }
  if ([((NSString *) nil_chk(format)) isEqual:@"RAW"]) {
    [self engineInitWithByteArray:params];
    return;
  }
  @throw new_JavaIoIOException_initWithNSString_(@"Unknown parameters format in IV parameters object");
}

- (NSString *)engineToString {
  return @"CAST5 Parameters";
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, 0, 1, 2, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x4, 3, 4, 5, -1, -1, -1 },
    { NULL, "V", 0x4, 6, 7, 5, -1, -1, -1 },
    { NULL, "V", 0x4, 6, 8, 2, -1, -1, -1 },
    { NULL, "V", 0x4, 6, 9, 2, -1, -1, -1 },
    { NULL, "LNSString;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineGetEncoded);
  methods[2].selector = @selector(engineGetEncodedWithNSString:);
  methods[3].selector = @selector(localEngineGetParameterSpecWithIOSClass:);
  methods[4].selector = @selector(engineInitWithJavaSecuritySpecAlgorithmParameterSpec:);
  methods[5].selector = @selector(engineInitWithByteArray:);
  methods[6].selector = @selector(engineInitWithByteArray:withNSString:);
  methods[7].selector = @selector(engineToString);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "iv_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "engineGetEncoded", "LNSString;", "LJavaIoIOException;", "localEngineGetParameterSpec", "LIOSClass;", "LJavaSecuritySpecInvalidParameterSpecException;", "engineInit", "LJavaSecuritySpecAlgorithmParameterSpec;", "[B", "[BLNSString;", "LLibOrgBouncycastleJcajceProviderSymmetricCAST5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams = { "AlgParams", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, fields, 7, 0x9, 8, 2, 10, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameters_init(self);
  self->keyLength_ = 128;
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams, init)
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings)

@implementation LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"AlgorithmParameters.CAST5" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_PREFIX, @"$AlgParams")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.AlgorithmParameters.1.2.840.113533.7.66.10" withNSString:@"CAST5"];
  [provider addAlgorithmWithNSString:@"AlgorithmParameterGenerator.CAST5" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_PREFIX, @"$AlgParamGen")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.AlgorithmParameterGenerator.1.2.840.113533.7.66.10" withNSString:@"CAST5"];
  [provider addAlgorithmWithNSString:@"Cipher.CAST5" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_PREFIX, @"$ECB")];
  [provider addAlgorithmWithNSString:@"Cipher" withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1MiscMiscObjectIdentifiers, cast5CBC) withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_PREFIX, @"$CBC")];
  [provider addAlgorithmWithNSString:@"KeyGenerator.CAST5" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_PREFIX, @"$KeyGen")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyGenerator" withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1MiscMiscObjectIdentifiers, cast5CBC) withNSString:@"CAST5"];
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
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", &LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_PREFIX, "LLibOrgBouncycastleJcajceProviderSymmetricCAST5;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings class]) {
    LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_PREFIX = [LibOrgBouncycastleJcajceProviderSymmetricCAST5_class_() getName];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings)
  }
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings, init)
}

LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings)
