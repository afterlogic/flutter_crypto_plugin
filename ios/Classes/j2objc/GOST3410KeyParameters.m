//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/GOST3410KeyParameters.java
//

#include "AsymmetricKeyParameter.h"
#include "GOST3410KeyParameters.h"
#include "GOST3410Parameters.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleCryptoParamsGOST3410KeyParameters () {
 @public
  LibOrgBouncycastleCryptoParamsGOST3410Parameters *params_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsGOST3410KeyParameters, params_, LibOrgBouncycastleCryptoParamsGOST3410Parameters *)

@implementation LibOrgBouncycastleCryptoParamsGOST3410KeyParameters

- (instancetype)initWithBoolean:(jboolean)isPrivate
withLibOrgBouncycastleCryptoParamsGOST3410Parameters:(LibOrgBouncycastleCryptoParamsGOST3410Parameters *)params {
  LibOrgBouncycastleCryptoParamsGOST3410KeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_(self, isPrivate, params);
  return self;
}

- (LibOrgBouncycastleCryptoParamsGOST3410Parameters *)getParameters {
  return params_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsGOST3410Parameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithBoolean:withLibOrgBouncycastleCryptoParamsGOST3410Parameters:);
  methods[1].selector = @selector(getParameters);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LLibOrgBouncycastleCryptoParamsGOST3410Parameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ZLLibOrgBouncycastleCryptoParamsGOST3410Parameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsGOST3410KeyParameters = { "GOST3410KeyParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsGOST3410KeyParameters;
}

@end

void LibOrgBouncycastleCryptoParamsGOST3410KeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_(LibOrgBouncycastleCryptoParamsGOST3410KeyParameters *self, jboolean isPrivate, LibOrgBouncycastleCryptoParamsGOST3410Parameters *params) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, isPrivate);
  self->params_ = params;
}

LibOrgBouncycastleCryptoParamsGOST3410KeyParameters *new_LibOrgBouncycastleCryptoParamsGOST3410KeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_(jboolean isPrivate, LibOrgBouncycastleCryptoParamsGOST3410Parameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsGOST3410KeyParameters, initWithBoolean_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_, isPrivate, params)
}

LibOrgBouncycastleCryptoParamsGOST3410KeyParameters *create_LibOrgBouncycastleCryptoParamsGOST3410KeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_(jboolean isPrivate, LibOrgBouncycastleCryptoParamsGOST3410Parameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsGOST3410KeyParameters, initWithBoolean_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_, isPrivate, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsGOST3410KeyParameters)
