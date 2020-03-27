//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/digest/RIPEMD320.java
//

#include "BCMessageDigest.h"
#include "BaseKeyGenerator.h"
#include "BaseMac.h"
#include "CipherKeyGenerator.h"
#include "ConfigurableProvider.h"
#include "Digest.h"
#include "DigestAlgorithmProvider.h"
#include "HMac.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "RIPEMD320.h"
#include "RIPEMD320Digest.h"

@interface LibOrgBouncycastleJcajceProviderDigestRIPEMD320 ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderDigestRIPEMD320_init(LibOrgBouncycastleJcajceProviderDigestRIPEMD320 *self);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderDigestRIPEMD320 *new_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderDigestRIPEMD320 *create_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_init(void);

inline NSString *LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings, PREFIX, NSString *)

@implementation LibOrgBouncycastleJcajceProviderDigestRIPEMD320

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestRIPEMD320_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest;LLibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac;LLibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator;LLibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestRIPEMD320 = { "RIPEMD320", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestRIPEMD320;
}

@end

void LibOrgBouncycastleJcajceProviderDigestRIPEMD320_init(LibOrgBouncycastleJcajceProviderDigestRIPEMD320 *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderDigestRIPEMD320 *new_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestRIPEMD320, init)
}

LibOrgBouncycastleJcajceProviderDigestRIPEMD320 *create_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestRIPEMD320, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestRIPEMD320)

@implementation LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id)java_clone {
  LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest *d = (LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest *) cast_chk([super java_clone], [LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest class]);
  ((LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest *) nil_chk(d))->digest_ = new_LibOrgBouncycastleCryptoDigestsRIPEMD320Digest_initWithLibOrgBouncycastleCryptoDigestsRIPEMD320Digest_((LibOrgBouncycastleCryptoDigestsRIPEMD320Digest *) cast_chk(digest_, [LibOrgBouncycastleCryptoDigestsRIPEMD320Digest class]));
  return d;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, 0, -1, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(java_clone);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "clone", "LJavaLangCloneNotSupportedException;", "LLibOrgBouncycastleJcajceProviderDigestRIPEMD320;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest = { "Digest", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest;
}

- (id)copyWithZone:(NSZone *)zone {
  return [self java_clone];
}

@end

void LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest_init(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest *self) {
  LibOrgBouncycastleJcajceProviderDigestBCMessageDigest_initWithLibOrgBouncycastleCryptoDigest_(self, new_LibOrgBouncycastleCryptoDigestsRIPEMD320Digest_init());
}

LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest *new_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest, init)
}

LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest *create_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Digest)

@implementation LibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestRIPEMD320;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac = { "HashMac", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac;
}

@end

void LibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac_init(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac_initWithLibOrgBouncycastleCryptoMac_(self, new_LibOrgBouncycastleCryptoMacsHMac_initWithLibOrgBouncycastleCryptoDigest_(new_LibOrgBouncycastleCryptoDigestsRIPEMD320Digest_init()));
}

LibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac *new_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac, init)
}

LibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac *create_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_HashMac)

@implementation LibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestRIPEMD320;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator = { "KeyGenerator", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator;
}

@end

void LibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator_init(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"HMACRIPEMD320", 320, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator *new_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator, init)
}

LibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator *create_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_KeyGenerator)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings)

@implementation LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"MessageDigest.RIPEMD320" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings_PREFIX, @"$Digest")];
  [self addHMACAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"RIPEMD320" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings_PREFIX, @"$HashMac") withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings_PREFIX, @"$KeyGenerator")];
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
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", &LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings_PREFIX, "LLibOrgBouncycastleJcajceProviderDigestRIPEMD320;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings class]) {
    LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings_PREFIX = [LibOrgBouncycastleJcajceProviderDigestRIPEMD320_class_() getName];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings)
  }
}

@end

void LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings_init(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings *self) {
  LibOrgBouncycastleJcajceProviderDigestDigestAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings *new_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings, init)
}

LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings *create_LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestRIPEMD320_Mappings)
