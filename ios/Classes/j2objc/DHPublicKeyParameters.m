//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/DHPublicKeyParameters.java
//

#include "DHKeyParameters.h"
#include "DHParameters.h"
#include "DHPublicKeyParameters.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/NullPointerException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoParamsDHPublicKeyParameters () {
 @public
  JavaMathBigInteger *y_;
}

- (JavaMathBigInteger *)validateWithJavaMathBigInteger:(JavaMathBigInteger *)y
        withLibOrgBouncycastleCryptoParamsDHParameters:(LibOrgBouncycastleCryptoParamsDHParameters *)dhParams;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters, y_, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_get_ONE(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_ONE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters, ONE, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_get_TWO(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_TWO;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters, TWO, JavaMathBigInteger *)

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_validateWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *self, JavaMathBigInteger *y, LibOrgBouncycastleCryptoParamsDHParameters *dhParams);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters)

@implementation LibOrgBouncycastleCryptoParamsDHPublicKeyParameters

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)y
withLibOrgBouncycastleCryptoParamsDHParameters:(LibOrgBouncycastleCryptoParamsDHParameters *)params {
  LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(self, y, params);
  return self;
}

- (JavaMathBigInteger *)validateWithJavaMathBigInteger:(JavaMathBigInteger *)y
        withLibOrgBouncycastleCryptoParamsDHParameters:(LibOrgBouncycastleCryptoParamsDHParameters *)dhParams {
  return LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_validateWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(self, y, dhParams);
}

- (JavaMathBigInteger *)getY {
  return y_;
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk(y_)) hash]) ^ ((jint) [super hash]);
}

- (jboolean)isEqual:(id)obj {
  if (!([obj isKindOfClass:[LibOrgBouncycastleCryptoParamsDHPublicKeyParameters class]])) {
    return false;
  }
  LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *other = (LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *) cast_chk(obj, [LibOrgBouncycastleCryptoParamsDHPublicKeyParameters class]);
  return [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *) nil_chk(other)) getY])) isEqual:y_] && [super isEqual:obj];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x2, 1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 3, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:withLibOrgBouncycastleCryptoParamsDHParameters:);
  methods[1].selector = @selector(validateWithJavaMathBigInteger:withLibOrgBouncycastleCryptoParamsDHParameters:);
  methods[2].selector = @selector(getY);
  methods[3].selector = @selector(hash);
  methods[4].selector = @selector(isEqual:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 5, -1, -1 },
    { "TWO", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 6, -1, -1 },
    { "y_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;LLibOrgBouncycastleCryptoParamsDHParameters;", "validate", "hashCode", "equals", "LNSObject;", &LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_ONE, &LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_TWO };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsDHPublicKeyParameters = { "DHPublicKeyParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 5, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoParamsDHPublicKeyParameters class]) {
    LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_TWO = JavaMathBigInteger_valueOfWithLong_(2);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters)
  }
}

@end

void LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *self, JavaMathBigInteger *y, LibOrgBouncycastleCryptoParamsDHParameters *params) {
  LibOrgBouncycastleCryptoParamsDHKeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsDHParameters_(self, false, params);
  self->y_ = LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_validateWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(self, y, params);
}

LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(JavaMathBigInteger *y, LibOrgBouncycastleCryptoParamsDHParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters, initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_, y, params)
}

LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *create_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(JavaMathBigInteger *y, LibOrgBouncycastleCryptoParamsDHParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters, initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_, y, params)
}

JavaMathBigInteger *LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_validateWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *self, JavaMathBigInteger *y, LibOrgBouncycastleCryptoParamsDHParameters *dhParams) {
  if (y == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"y value cannot be null");
  }
  if ([y compareToWithId:LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_TWO] < 0 || [y compareToWithId:[((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsDHParameters *) nil_chk(dhParams)) getP])) subtractWithJavaMathBigInteger:LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_TWO]] > 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"invalid DH public key");
  }
  if ([((LibOrgBouncycastleCryptoParamsDHParameters *) nil_chk(dhParams)) getQ] != nil) {
    if ([((JavaMathBigInteger *) nil_chk(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_ONE)) isEqual:[y modPowWithJavaMathBigInteger:[dhParams getQ] withJavaMathBigInteger:[dhParams getP]]]) {
      return y;
    }
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Y value does not appear to be in correct group");
  }
  else {
    return y;
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters)
