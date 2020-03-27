//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/ElGamalPublicKeyParameters.java
//

#include "ElGamalKeyParameters.h"
#include "ElGamalParameters.h"
#include "ElGamalPublicKeyParameters.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters () {
 @public
  JavaMathBigInteger *y_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters, y_, JavaMathBigInteger *)

@implementation LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)y
withLibOrgBouncycastleCryptoParamsElGamalParameters:(LibOrgBouncycastleCryptoParamsElGamalParameters *)params {
  LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsElGamalParameters_(self, y, params);
  return self;
}

- (JavaMathBigInteger *)getY {
  return y_;
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk(y_)) hash]) ^ ((jint) [super hash]);
}

- (jboolean)isEqual:(id)obj {
  if (!([obj isKindOfClass:[LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters class]])) {
    return false;
  }
  LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters *other = (LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters *) cast_chk(obj, [LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters class]);
  return [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters *) nil_chk(other)) getY])) isEqual:y_] && [super isEqual:obj];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:withLibOrgBouncycastleCryptoParamsElGamalParameters:);
  methods[1].selector = @selector(getY);
  methods[2].selector = @selector(hash);
  methods[3].selector = @selector(isEqual:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "y_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;LLibOrgBouncycastleCryptoParamsElGamalParameters;", "hashCode", "equals", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters = { "ElGamalPublicKeyParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters;
}

@end

void LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsElGamalParameters_(LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters *self, JavaMathBigInteger *y, LibOrgBouncycastleCryptoParamsElGamalParameters *params) {
  LibOrgBouncycastleCryptoParamsElGamalKeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsElGamalParameters_(self, false, params);
  self->y_ = y;
}

LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters *new_LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsElGamalParameters_(JavaMathBigInteger *y, LibOrgBouncycastleCryptoParamsElGamalParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters, initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsElGamalParameters_, y, params)
}

LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters *create_LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsElGamalParameters_(JavaMathBigInteger *y, LibOrgBouncycastleCryptoParamsElGamalParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters, initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsElGamalParameters_, y, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters)
