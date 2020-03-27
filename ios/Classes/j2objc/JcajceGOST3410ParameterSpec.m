//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/spec/JcajceGOST3410ParameterSpec.java
//

#include "ASN1ObjectIdentifier.h"
#include "CryptoProObjectIdentifiers.h"
#include "ECGOST3410NamedCurves.h"
#include "J2ObjC_source.h"
#include "JcajceGOST3410ParameterSpec.h"
#include "RosstandartObjectIdentifiers.h"

@interface LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet_;
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet_;
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionParamSet_;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getOidWithNSString:(NSString *)paramName;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getDigestOidWithNSString:(NSString *)paramName;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec, publicKeyParamSet_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec, digestParamSet_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec, encryptionParamSet_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

__attribute__((unused)) static LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_getOidWithNSString_(NSString *paramName);

__attribute__((unused)) static LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_getDigestOidWithNSString_(NSString *paramName);

@implementation LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec

- (instancetype)initWithNSString:(NSString *)publicKeyParamSet {
  LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithNSString_(self, publicKeyParamSet);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)publicKeyParamSet
                    withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)digestParamSet {
  LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, publicKeyParamSet, digestParamSet);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)publicKeyParamSet
                    withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)digestParamSet
                    withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)encryptionParamSet {
  LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, publicKeyParamSet, digestParamSet, encryptionParamSet);
  return self;
}

- (NSString *)getPublicKeyParamSetName {
  return LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_([self getPublicKeyParamSet]);
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getPublicKeyParamSet {
  return publicKeyParamSet_;
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getDigestParamSet {
  return digestParamSet_;
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getEncryptionParamSet {
  return encryptionParamSet_;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getOidWithNSString:(NSString *)paramName {
  return LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_getOidWithNSString_(paramName);
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getDigestOidWithNSString:(NSString *)paramName {
  return LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_getDigestOidWithNSString_(paramName);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0xa, 3, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0xa, 4, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[3].selector = @selector(getPublicKeyParamSetName);
  methods[4].selector = @selector(getPublicKeyParamSet);
  methods[5].selector = @selector(getDigestParamSet);
  methods[6].selector = @selector(getEncryptionParamSet);
  methods[7].selector = @selector(getOidWithNSString:);
  methods[8].selector = @selector(getDigestOidWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "publicKeyParamSet_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "digestParamSet_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "encryptionParamSet_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "getOid", "getDigestOid" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec = { "JcajceGOST3410ParameterSpec", "lib.org.bouncycastle.jcajce.spec", ptrTable, methods, fields, 7, 0x1, 9, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec;
}

@end

void LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithNSString_(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *self, NSString *publicKeyParamSet) {
  LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_getOidWithNSString_(publicKeyParamSet), LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_getDigestOidWithNSString_(publicKeyParamSet), nil);
}

LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *new_LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithNSString_(NSString *publicKeyParamSet) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec, initWithNSString_, publicKeyParamSet)
}

LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *create_LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithNSString_(NSString *publicKeyParamSet) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec, initWithNSString_, publicKeyParamSet)
}

void LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet) {
  LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, publicKeyParamSet, digestParamSet, nil);
}

LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *new_LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, publicKeyParamSet, digestParamSet)
}

LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *create_LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, publicKeyParamSet, digestParamSet)
}

void LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionParamSet) {
  NSObject_init(self);
  self->publicKeyParamSet_ = publicKeyParamSet;
  self->digestParamSet_ = digestParamSet;
  self->encryptionParamSet_ = encryptionParamSet;
}

LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *new_LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionParamSet) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, publicKeyParamSet, digestParamSet, encryptionParamSet)
}

LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *create_LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionParamSet) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, publicKeyParamSet, digestParamSet, encryptionParamSet)
}

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_getOidWithNSString_(NSString *paramName) {
  LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initialize();
  return LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getOIDWithNSString_(paramName);
}

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_getDigestOidWithNSString_(NSString *paramName) {
  LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initialize();
  if ([((NSString *) nil_chk(paramName)) java_indexOfString:@"12-512"] > 0) {
    return JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3411_12_512);
  }
  if ([paramName java_indexOfString:@"12-256"] > 0) {
    return JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3411_12_256);
  }
  return JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3411_94_CryptoProParamSet);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec)
