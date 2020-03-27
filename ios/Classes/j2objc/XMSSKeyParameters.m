//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/XMSSKeyParameters.java
//

#include "AsymmetricKeyParameter.h"
#include "J2ObjC_source.h"
#include "XMSSKeyParameters.h"

@interface LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters () {
 @public
  NSString *treeDigest_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters, treeDigest_, NSString *)

NSString *LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_SHA_256 = @"SHA-256";
NSString *LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_SHA_512 = @"SHA-512";
NSString *LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_SHAKE128 = @"SHAKE128";
NSString *LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_SHAKE256 = @"SHAKE256";

@implementation LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters

+ (NSString *)SHA_256 {
  return LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_SHA_256;
}

+ (NSString *)SHA_512 {
  return LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_SHA_512;
}

+ (NSString *)SHAKE128 {
  return LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_SHAKE128;
}

+ (NSString *)SHAKE256 {
  return LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_SHAKE256;
}

- (instancetype)initWithBoolean:(jboolean)isPrivateKey
                   withNSString:(NSString *)treeDigest {
  LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_initWithBoolean_withNSString_(self, isPrivateKey, treeDigest);
  return self;
}

- (NSString *)getTreeDigest {
  return treeDigest_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithBoolean:withNSString:);
  methods[1].selector = @selector(getTreeDigest);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "SHA_256", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 1, -1, -1 },
    { "SHA_512", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 2, -1, -1 },
    { "SHAKE128", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 3, -1, -1 },
    { "SHAKE256", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 4, -1, -1 },
    { "treeDigest_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ZLNSString;", &LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_SHA_256, &LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_SHA_512, &LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_SHAKE128, &LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_SHAKE256 };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters = { "XMSSKeyParameters", "lib.org.bouncycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x1, 2, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters;
}

@end

void LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_initWithBoolean_withNSString_(LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters *self, jboolean isPrivateKey, NSString *treeDigest) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, isPrivateKey);
  self->treeDigest_ = treeDigest;
}

LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters *new_LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_initWithBoolean_withNSString_(jboolean isPrivateKey, NSString *treeDigest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters, initWithBoolean_withNSString_, isPrivateKey, treeDigest)
}

LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters *create_LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_initWithBoolean_withNSString_(jboolean isPrivateKey, NSString *treeDigest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters, initWithBoolean_withNSString_, isPrivateKey, treeDigest)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters)
