//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/digest/Keccak.java
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
#include "Keccak.h"
#include "KeccakDigest.h"

@interface LibOrgBouncycastleJcajceProviderDigestKeccak ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderDigestKeccak_init(LibOrgBouncycastleJcajceProviderDigestKeccak *self);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderDigestKeccak *new_LibOrgBouncycastleJcajceProviderDigestKeccak_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderDigestKeccak *create_LibOrgBouncycastleJcajceProviderDigestKeccak_init(void);

inline NSString *LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings, PREFIX, NSString *)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak;LLibOrgBouncycastleJcajceProviderDigestKeccak_Digest224;LLibOrgBouncycastleJcajceProviderDigestKeccak_Digest256;LLibOrgBouncycastleJcajceProviderDigestKeccak_Digest288;LLibOrgBouncycastleJcajceProviderDigestKeccak_Digest384;LLibOrgBouncycastleJcajceProviderDigestKeccak_Digest512;LLibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224;LLibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256;LLibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288;LLibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384;LLibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512;LLibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224;LLibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256;LLibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288;LLibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384;LLibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512;LLibOrgBouncycastleJcajceProviderDigestKeccak_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak = { "Keccak", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_init(LibOrgBouncycastleJcajceProviderDigestKeccak *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderDigestKeccak *new_LibOrgBouncycastleJcajceProviderDigestKeccak_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak *create_LibOrgBouncycastleJcajceProviderDigestKeccak_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak

- (instancetype)initWithInt:(jint)size {
  LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak_initWithInt_(self, size);
  return self;
}

- (id)java_clone {
  LibOrgBouncycastleJcajceProviderDigestBCMessageDigest *d = (LibOrgBouncycastleJcajceProviderDigestBCMessageDigest *) cast_chk([super java_clone], [LibOrgBouncycastleJcajceProviderDigestBCMessageDigest class]);
  ((LibOrgBouncycastleJcajceProviderDigestBCMessageDigest *) nil_chk(d))->digest_ = new_LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithLibOrgBouncycastleCryptoDigestsKeccakDigest_((LibOrgBouncycastleCryptoDigestsKeccakDigest *) cast_chk(digest_, [LibOrgBouncycastleCryptoDigestsKeccakDigest class]));
  return d;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, 1, -1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:);
  methods[1].selector = @selector(java_clone);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "I", "clone", "LJavaLangCloneNotSupportedException;", "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak = { "DigestKeccak", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 2, 0, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak;
}

- (id)copyWithZone:(NSZone *)zone {
  return [self java_clone];
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak_initWithInt_(LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak *self, jint size) {
  LibOrgBouncycastleJcajceProviderDigestBCMessageDigest_initWithLibOrgBouncycastleCryptoDigest_(self, new_LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithInt_(size));
}

LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak *new_LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak_initWithInt_(jint size) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak, initWithInt_, size)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak *create_LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak_initWithInt_(jint size) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak, initWithInt_, size)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_Digest224

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_Digest224_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_Digest224 = { "Digest224", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest224;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_Digest224_init(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest224 *self) {
  LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak_initWithInt_(self, 224);
}

LibOrgBouncycastleJcajceProviderDigestKeccak_Digest224 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest224_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest224, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_Digest224 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest224_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest224, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest224)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_Digest256

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_Digest256_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_Digest256 = { "Digest256", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest256;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_Digest256_init(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest256 *self) {
  LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak_initWithInt_(self, 256);
}

LibOrgBouncycastleJcajceProviderDigestKeccak_Digest256 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest256_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest256, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_Digest256 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest256_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest256, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest256)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_Digest288

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_Digest288_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_Digest288 = { "Digest288", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest288;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_Digest288_init(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest288 *self) {
  LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak_initWithInt_(self, 288);
}

LibOrgBouncycastleJcajceProviderDigestKeccak_Digest288 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest288_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest288, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_Digest288 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest288_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest288, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest288)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_Digest384

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_Digest384_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_Digest384 = { "Digest384", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest384;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_Digest384_init(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest384 *self) {
  LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak_initWithInt_(self, 384);
}

LibOrgBouncycastleJcajceProviderDigestKeccak_Digest384 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest384_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest384, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_Digest384 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest384_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest384, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest384)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_Digest512

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_Digest512_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_Digest512 = { "Digest512", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest512;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_Digest512_init(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest512 *self) {
  LibOrgBouncycastleJcajceProviderDigestKeccak_DigestKeccak_initWithInt_(self, 512);
}

LibOrgBouncycastleJcajceProviderDigestKeccak_Digest512 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest512_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest512, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_Digest512 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_Digest512_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest512, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_Digest512)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224 = { "HashMac224", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224_init(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac_initWithLibOrgBouncycastleCryptoMac_(self, new_LibOrgBouncycastleCryptoMacsHMac_initWithLibOrgBouncycastleCryptoDigest_(new_LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithInt_(224)));
}

LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac224)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256 = { "HashMac256", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256_init(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac_initWithLibOrgBouncycastleCryptoMac_(self, new_LibOrgBouncycastleCryptoMacsHMac_initWithLibOrgBouncycastleCryptoDigest_(new_LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithInt_(256)));
}

LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac256)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288 = { "HashMac288", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288_init(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac_initWithLibOrgBouncycastleCryptoMac_(self, new_LibOrgBouncycastleCryptoMacsHMac_initWithLibOrgBouncycastleCryptoDigest_(new_LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithInt_(288)));
}

LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac288)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384 = { "HashMac384", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384_init(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac_initWithLibOrgBouncycastleCryptoMac_(self, new_LibOrgBouncycastleCryptoMacsHMac_initWithLibOrgBouncycastleCryptoDigest_(new_LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithInt_(384)));
}

LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac384)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512 = { "HashMac512", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512_init(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac_initWithLibOrgBouncycastleCryptoMac_(self, new_LibOrgBouncycastleCryptoMacsHMac_initWithLibOrgBouncycastleCryptoDigest_(new_LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithInt_(512)));
}

LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_HashMac512)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224 = { "KeyGenerator224", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224_init(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"HMACKECCAK224", 224, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator224)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256 = { "KeyGenerator256", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256_init(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"HMACKECCAK256", 256, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator256)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288 = { "KeyGenerator288", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288_init(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"HMACKECCAK288", 288, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator288)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384 = { "KeyGenerator384", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384_init(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"HMACKECCAK384", 384, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator384)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512 = { "KeyGenerator512", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512;
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512_init(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"HMACKECCAK512", 512, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512 *new_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512 *create_LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_KeyGenerator512)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings)

@implementation LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"MessageDigest.KECCAK-224" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$Digest224")];
  [provider addAlgorithmWithNSString:@"MessageDigest.KECCAK-288" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$Digest288")];
  [provider addAlgorithmWithNSString:@"MessageDigest.KECCAK-256" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$Digest256")];
  [provider addAlgorithmWithNSString:@"MessageDigest.KECCAK-384" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$Digest384")];
  [provider addAlgorithmWithNSString:@"MessageDigest.KECCAK-512" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$Digest512")];
  [self addHMACAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"KECCAK224" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$HashMac224") withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$KeyGenerator224")];
  [self addHMACAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"KECCAK256" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$HashMac256") withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$KeyGenerator256")];
  [self addHMACAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"KECCAK288" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$HashMac288") withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$KeyGenerator288")];
  [self addHMACAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"KECCAK384" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$HashMac384") withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$KeyGenerator384")];
  [self addHMACAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"KECCAK512" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$HashMac512") withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, @"$KeyGenerator512")];
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
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", &LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX, "LLibOrgBouncycastleJcajceProviderDigestKeccak;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.digest", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings class]) {
    LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_PREFIX = [LibOrgBouncycastleJcajceProviderDigestKeccak_class_() getName];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings)
  }
}

@end

void LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_init(LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings *self) {
  LibOrgBouncycastleJcajceProviderDigestDigestAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings *new_LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings, init)
}

LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings *create_LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderDigestKeccak_Mappings)
