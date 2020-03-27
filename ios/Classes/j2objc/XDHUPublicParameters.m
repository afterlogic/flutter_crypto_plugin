//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/XDHUPublicParameters.java
//

#include "AsymmetricKeyParameter.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "X25519PublicKeyParameters.h"
#include "X448PublicKeyParameters.h"
#include "XDHUPublicParameters.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/NullPointerException.h"

@interface LibOrgBouncycastleCryptoParamsXDHUPublicParameters () {
 @public
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *staticPublicKey_;
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPublicKey_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsXDHUPublicParameters, staticPublicKey_, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsXDHUPublicParameters, ephemeralPublicKey_, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)

@implementation LibOrgBouncycastleCryptoParamsXDHUPublicParameters

- (instancetype)initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)staticPublicKey
                    withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)ephemeralPublicKey {
  LibOrgBouncycastleCryptoParamsXDHUPublicParameters_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(self, staticPublicKey, ephemeralPublicKey);
  return self;
}

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getStaticPublicKey {
  return staticPublicKey_;
}

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getEphemeralPublicKey {
  return ephemeralPublicKey_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:);
  methods[1].selector = @selector(getStaticPublicKey);
  methods[2].selector = @selector(getEphemeralPublicKey);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "staticPublicKey_", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ephemeralPublicKey_", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsXDHUPublicParameters = { "XDHUPublicParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 3, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsXDHUPublicParameters;
}

@end

void LibOrgBouncycastleCryptoParamsXDHUPublicParameters_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsXDHUPublicParameters *self, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *staticPublicKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPublicKey) {
  NSObject_init(self);
  if (staticPublicKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"staticPublicKey cannot be null");
  }
  if (!([staticPublicKey isKindOfClass:[LibOrgBouncycastleCryptoParamsX448PublicKeyParameters class]] || [staticPublicKey isKindOfClass:[LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters class]])) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"only X25519 and X448 paramaters can be used");
  }
  if (ephemeralPublicKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"ephemeralPublicKey cannot be null");
  }
  if (![[staticPublicKey java_getClass] isAssignableFrom:[ephemeralPublicKey java_getClass]]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"static and ephemeral public keys have different domain parameters");
  }
  self->staticPublicKey_ = staticPublicKey;
  self->ephemeralPublicKey_ = ephemeralPublicKey;
}

LibOrgBouncycastleCryptoParamsXDHUPublicParameters *new_LibOrgBouncycastleCryptoParamsXDHUPublicParameters_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *staticPublicKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPublicKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsXDHUPublicParameters, initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_, staticPublicKey, ephemeralPublicKey)
}

LibOrgBouncycastleCryptoParamsXDHUPublicParameters *create_LibOrgBouncycastleCryptoParamsXDHUPublicParameters_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *staticPublicKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPublicKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsXDHUPublicParameters, initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_, staticPublicKey, ephemeralPublicKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsXDHUPublicParameters)