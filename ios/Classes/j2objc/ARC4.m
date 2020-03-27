//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/ARC4.java
//

#include "ARC4.h"
#include "ASN1ObjectIdentifier.h"
#include "AlgorithmProvider.h"
#include "BaseKeyGenerator.h"
#include "BaseStreamCipher.h"
#include "CipherKeyGenerator.h"
#include "ConfigurableProvider.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "PBE.h"
#include "PBESecretKeyFactory.h"
#include "PKCSObjectIdentifiers.h"
#include "RC4Engine.h"

@interface LibOrgBouncycastleJcajceProviderSymmetricARC4 ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderSymmetricARC4_init(LibOrgBouncycastleJcajceProviderSymmetricARC4 *self);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricARC4 *new_LibOrgBouncycastleJcajceProviderSymmetricARC4_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricARC4 *create_LibOrgBouncycastleJcajceProviderSymmetricARC4_init(void);

inline NSString *LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings, PREFIX, NSString *)

@implementation LibOrgBouncycastleJcajceProviderSymmetricARC4

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricARC4_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricARC4_Base;LLibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen;LLibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory;LLibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory;LLibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit;LLibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit;LLibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricARC4 = { "ARC4", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x11, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricARC4;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricARC4_init(LibOrgBouncycastleJcajceProviderSymmetricARC4 *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricARC4 *new_LibOrgBouncycastleJcajceProviderSymmetricARC4_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4, init)
}

LibOrgBouncycastleJcajceProviderSymmetricARC4 *create_LibOrgBouncycastleJcajceProviderSymmetricARC4_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricARC4)

@implementation LibOrgBouncycastleJcajceProviderSymmetricARC4_Base

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricARC4_Base_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricARC4;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricARC4_Base = { "Base", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricARC4_Base;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricARC4_Base_init(LibOrgBouncycastleJcajceProviderSymmetricARC4_Base *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseStreamCipher_initWithLibOrgBouncycastleCryptoStreamCipher_withInt_(self, new_LibOrgBouncycastleCryptoEnginesRC4Engine_init(), 0);
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_Base *new_LibOrgBouncycastleJcajceProviderSymmetricARC4_Base_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_Base, init)
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_Base *create_LibOrgBouncycastleJcajceProviderSymmetricARC4_Base_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_Base, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricARC4_Base)

@implementation LibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricARC4;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen = { "KeyGen", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen_init(LibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"RC4", 128, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen *new_LibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen, init)
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen *create_LibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricARC4_KeyGen)

@implementation LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricARC4;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory = { "PBEWithSHAAnd128BitKeyFactory", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory_init(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilPBESecretKeyFactory_initWithNSString_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withInt_withInt_withInt_withInt_(self, @"PBEWithSHAAnd128BitRC4", JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, pbeWithSHAAnd128BitRC4), true, LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_PKCS12, LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA1, 128, 0);
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory *new_LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory, init)
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory *create_LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128BitKeyFactory)

@implementation LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricARC4;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory = { "PBEWithSHAAnd40BitKeyFactory", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory_init(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilPBESecretKeyFactory_initWithNSString_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withInt_withInt_withInt_withInt_(self, @"PBEWithSHAAnd128BitRC4", JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, pbeWithSHAAnd128BitRC4), true, LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_PKCS12, LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA1, 40, 0);
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory *new_LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory, init)
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory *create_LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40BitKeyFactory)

@implementation LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricARC4;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit = { "PBEWithSHAAnd128Bit", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit_init(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseStreamCipher_initWithLibOrgBouncycastleCryptoStreamCipher_withInt_withInt_withInt_(self, new_LibOrgBouncycastleCryptoEnginesRC4Engine_init(), 0, 128, LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA1);
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit *new_LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit, init)
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit *create_LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd128Bit)

@implementation LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricARC4;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit = { "PBEWithSHAAnd40Bit", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit_init(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseStreamCipher_initWithLibOrgBouncycastleCryptoStreamCipher_withInt_withInt_withInt_(self, new_LibOrgBouncycastleCryptoEnginesRC4Engine_init(), 0, 40, LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA1);
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit *new_LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit, init)
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit *create_LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricARC4_PBEWithSHAAnd40Bit)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings)

@implementation LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"Cipher.ARC4" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_PREFIX, @"$Base")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Cipher" withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, rc4) withNSString:@"ARC4"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Cipher.ARCFOUR" withNSString:@"ARC4"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Cipher.RC4" withNSString:@"ARC4"];
  [provider addAlgorithmWithNSString:@"KeyGenerator.ARC4" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_PREFIX, @"$KeyGen")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyGenerator.RC4" withNSString:@"ARC4"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyGenerator.1.2.840.113549.3.4" withNSString:@"ARC4"];
  [provider addAlgorithmWithNSString:@"SecretKeyFactory.PBEWITHSHAAND128BITRC4" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_PREFIX, @"$PBEWithSHAAnd128BitKeyFactory")];
  [provider addAlgorithmWithNSString:@"SecretKeyFactory.PBEWITHSHAAND40BITRC4" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_PREFIX, @"$PBEWithSHAAnd40BitKeyFactory")];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.AlgorithmParameters.", JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, pbeWithSHAAnd128BitRC4)) withNSString:@"PKCS12PBE"];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.AlgorithmParameters.", JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, pbeWithSHAAnd40BitRC4)) withNSString:@"PKCS12PBE"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.AlgorithmParameters.PBEWITHSHAAND40BITRC4" withNSString:@"PKCS12PBE"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.AlgorithmParameters.PBEWITHSHAAND128BITRC4" withNSString:@"PKCS12PBE"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.AlgorithmParameters.PBEWITHSHAANDRC4" withNSString:@"PKCS12PBE"];
  [provider addAlgorithmWithNSString:@"Cipher.PBEWITHSHAAND128BITRC4" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_PREFIX, @"$PBEWithSHAAnd128Bit")];
  [provider addAlgorithmWithNSString:@"Cipher.PBEWITHSHAAND40BITRC4" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_PREFIX, @"$PBEWithSHAAnd40Bit")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.SecretKeyFactory" withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, pbeWithSHAAnd128BitRC4) withNSString:@"PBEWITHSHAAND128BITRC4"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.SecretKeyFactory" withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, pbeWithSHAAnd40BitRC4) withNSString:@"PBEWITHSHAAND40BITRC4"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Cipher.PBEWITHSHA1AND128BITRC4" withNSString:@"PBEWITHSHAAND128BITRC4"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Cipher.PBEWITHSHA1AND40BITRC4" withNSString:@"PBEWITHSHAAND40BITRC4"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Cipher" withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, pbeWithSHAAnd128BitRC4) withNSString:@"PBEWITHSHAAND128BITRC4"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Cipher" withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, pbeWithSHAAnd40BitRC4) withNSString:@"PBEWITHSHAAND40BITRC4"];
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
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", &LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_PREFIX, "LLibOrgBouncycastleJcajceProviderSymmetricARC4;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings class]) {
    LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_PREFIX = [LibOrgBouncycastleJcajceProviderSymmetricARC4_class_() getName];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings)
  }
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings, init)
}

LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricARC4_Mappings)
