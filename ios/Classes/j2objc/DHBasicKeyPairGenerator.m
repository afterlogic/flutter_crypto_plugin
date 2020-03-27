//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/DHBasicKeyPairGenerator.java
//

#include "AsymmetricCipherKeyPair.h"
#include "DHBasicKeyPairGenerator.h"
#include "DHKeyGenerationParameters.h"
#include "DHKeyGeneratorHelper.h"
#include "DHParameters.h"
#include "DHPrivateKeyParameters.h"
#include "DHPublicKeyParameters.h"
#include "J2ObjC_source.h"
#include "KeyGenerationParameters.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator () {
 @public
  LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *param_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator, param_, LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *)

@implementation LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param {
  self->param_ = (LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters class]);
}

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair {
  LibOrgBouncycastleCryptoGeneratorsDHKeyGeneratorHelper *helper = JreLoadStatic(LibOrgBouncycastleCryptoGeneratorsDHKeyGeneratorHelper, INSTANCE);
  LibOrgBouncycastleCryptoParamsDHParameters *dhp = [((LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *) nil_chk(param_)) getParameters];
  JavaMathBigInteger *x = [((LibOrgBouncycastleCryptoGeneratorsDHKeyGeneratorHelper *) nil_chk(helper)) calculatePrivateWithLibOrgBouncycastleCryptoParamsDHParameters:dhp withJavaSecuritySecureRandom:[((LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *) nil_chk(param_)) getRandom]];
  JavaMathBigInteger *y = [helper calculatePublicWithLibOrgBouncycastleCryptoParamsDHParameters:dhp withJavaMathBigInteger:x];
  return new_LibOrgBouncycastleCryptoAsymmetricCipherKeyPair_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(y, dhp), new_LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(x, dhp));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoAsymmetricCipherKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:);
  methods[2].selector = @selector(generateKeyPair);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "param_", "LLibOrgBouncycastleCryptoParamsDHKeyGenerationParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoKeyGenerationParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator = { "DHBasicKeyPairGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator;
}

@end

void LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator_init(LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator *new_LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator, init)
}

LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator *create_LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator)
