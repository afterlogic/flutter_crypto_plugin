//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/TEA.java
//

#include "AlgorithmProvider.h"
#include "BaseBlockCipher.h"
#include "BaseKeyGenerator.h"
#include "CipherKeyGenerator.h"
#include "ConfigurableProvider.h"
#include "IOSClass.h"
#include "IvAlgorithmParameters.h"
#include "J2ObjC_source.h"
#include "TEA.h"
#include "TEAEngine.h"

@interface LibOrgBouncycastleJcajceProviderSymmetricTEA ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderSymmetricTEA_init(LibOrgBouncycastleJcajceProviderSymmetricTEA *self);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricTEA *new_LibOrgBouncycastleJcajceProviderSymmetricTEA_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricTEA *create_LibOrgBouncycastleJcajceProviderSymmetricTEA_init(void);

inline NSString *LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings, PREFIX, NSString *)

@implementation LibOrgBouncycastleJcajceProviderSymmetricTEA

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricTEA_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricTEA_ECB;LLibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen;LLibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams;LLibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricTEA = { "TEA", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x11, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricTEA;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricTEA_init(LibOrgBouncycastleJcajceProviderSymmetricTEA *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricTEA *new_LibOrgBouncycastleJcajceProviderSymmetricTEA_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricTEA, init)
}

LibOrgBouncycastleJcajceProviderSymmetricTEA *create_LibOrgBouncycastleJcajceProviderSymmetricTEA_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricTEA, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricTEA)

@implementation LibOrgBouncycastleJcajceProviderSymmetricTEA_ECB

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricTEA_ECB_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricTEA;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricTEA_ECB = { "ECB", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricTEA_ECB;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricTEA_ECB_init(LibOrgBouncycastleJcajceProviderSymmetricTEA_ECB *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, new_LibOrgBouncycastleCryptoEnginesTEAEngine_init());
}

LibOrgBouncycastleJcajceProviderSymmetricTEA_ECB *new_LibOrgBouncycastleJcajceProviderSymmetricTEA_ECB_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricTEA_ECB, init)
}

LibOrgBouncycastleJcajceProviderSymmetricTEA_ECB *create_LibOrgBouncycastleJcajceProviderSymmetricTEA_ECB_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricTEA_ECB, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricTEA_ECB)

@implementation LibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricTEA;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen = { "KeyGen", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen_init(LibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"TEA", 128, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen *new_LibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen, init)
}

LibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen *create_LibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricTEA_KeyGen)

@implementation LibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (NSString *)engineToString {
  return @"TEA IV";
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricTEA;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams = { "AlgParams", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 2, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams_init(LibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilIvAlgorithmParameters_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams *new_LibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams, init)
}

LibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams *create_LibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricTEA_AlgParams)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings)

@implementation LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"Cipher.TEA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings_PREFIX, @"$ECB")];
  [provider addAlgorithmWithNSString:@"KeyGenerator.TEA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings_PREFIX, @"$KeyGen")];
  [provider addAlgorithmWithNSString:@"AlgorithmParameters.TEA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings_PREFIX, @"$AlgParams")];
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
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", &LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings_PREFIX, "LLibOrgBouncycastleJcajceProviderSymmetricTEA;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings class]) {
    LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings_PREFIX = [LibOrgBouncycastleJcajceProviderSymmetricTEA_class_() getName];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings)
  }
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings, init)
}

LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricTEA_Mappings)
