//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/RSABlindingFactorGenerator.java
//

#include "BigIntegers.h"
#include "CipherParameters.h"
#include "CryptoServicesRegistrar.h"
#include "J2ObjC_source.h"
#include "ParametersWithRandom.h"
#include "RSABlindingFactorGenerator.h"
#include "RSAKeyParameters.h"
#include "RSAPrivateCrtKeyParameters.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator () {
 @public
  LibOrgBouncycastleCryptoParamsRSAKeyParameters *key_;
  JavaSecuritySecureRandom *random_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator, key_, LibOrgBouncycastleCryptoParamsRSAKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator, random_, JavaSecuritySecureRandom *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_get_ZERO(void);
inline JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_set_ZERO(JavaMathBigInteger *value);
static JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_ZERO;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator, ZERO, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_get_ONE(void);
inline JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_set_ONE(JavaMathBigInteger *value);
static JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_ONE;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator, ONE, JavaMathBigInteger *)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator)

@implementation LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param {
  if ([param isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithRandom class]]) {
    LibOrgBouncycastleCryptoParamsParametersWithRandom *rParam = (LibOrgBouncycastleCryptoParamsParametersWithRandom *) param;
    key_ = (LibOrgBouncycastleCryptoParamsRSAKeyParameters *) cast_chk([((LibOrgBouncycastleCryptoParamsParametersWithRandom *) nil_chk(rParam)) getParameters], [LibOrgBouncycastleCryptoParamsRSAKeyParameters class]);
    random_ = [rParam getRandom];
  }
  else {
    key_ = (LibOrgBouncycastleCryptoParamsRSAKeyParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsRSAKeyParameters class]);
    random_ = LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom();
  }
  if ([key_ isKindOfClass:[LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters class]]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"generator requires RSA public key");
  }
}

- (JavaMathBigInteger *)generateBlindingFactor {
  if (key_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"generator not initialised");
  }
  JavaMathBigInteger *m = [key_ getModulus];
  jint length = [((JavaMathBigInteger *) nil_chk(m)) bitLength] - 1;
  JavaMathBigInteger *factor;
  JavaMathBigInteger *gcd;
  do {
    factor = LibOrgBouncycastleUtilBigIntegers_createRandomBigIntegerWithInt_withJavaSecuritySecureRandom_(length, random_);
    gcd = [((JavaMathBigInteger *) nil_chk(factor)) gcdWithJavaMathBigInteger:m];
  }
  while ([factor isEqual:LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_ZERO] || [factor isEqual:LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_ONE] || ![((JavaMathBigInteger *) nil_chk(gcd)) isEqual:LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_ONE]);
  return factor;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(generateBlindingFactor);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ZERO", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0xa, -1, 2, -1, -1 },
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0xa, -1, 3, -1, -1 },
    { "key_", "LLibOrgBouncycastleCryptoParamsRSAKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoCipherParameters;", &LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_ZERO, &LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_ONE };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator = { "RSABlindingFactorGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 3, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator class]) {
    LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_ZERO = JavaMathBigInteger_valueOfWithLong_(0);
    LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator)
  }
}

@end

void LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_init(LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator *new_LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator, init)
}

LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator *create_LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsRSABlindingFactorGenerator)
