//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/rainbow/RainbowKeyPairGeneratorSpi.java
//

#include "AsymmetricCipherKeyPair.h"
#include "AsymmetricKeyParameter.h"
#include "BCRainbowPrivateKey.h"
#include "BCRainbowPublicKey.h"
#include "CryptoServicesRegistrar.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "RainbowKeyGenerationParameters.h"
#include "RainbowKeyPairGenerator.h"
#include "RainbowKeyPairGeneratorSpi.h"
#include "RainbowParameterSpec.h"
#include "RainbowParameters.h"
#include "RainbowPrivateKeyParameters.h"
#include "RainbowPublicKeyParameters.h"
#include "java/security/InvalidAlgorithmParameterException.h"
#include "java/security/KeyPair.h"
#include "java/security/KeyPairGenerator.h"
#include "java/security/SecureRandom.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@implementation LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)initialize__WithInt:(jint)strength
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  self->strength_ = strength;
  self->random_ = random;
}

- (void)initialize__WithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
                                  withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  if (!([params isKindOfClass:[LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec class]])) {
    @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_(@"parameter object not a RainbowParameterSpec");
  }
  LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec *rainbowParams = (LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec *) cast_chk(params, [LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec class]);
  param_ = new_LibOrgBouncycastlePqcCryptoRainbowRainbowKeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastlePqcCryptoRainbowRainbowParameters_(random, new_LibOrgBouncycastlePqcCryptoRainbowRainbowParameters_initWithIntArray_([((LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec *) nil_chk(rainbowParams)) getVi]));
  [((LibOrgBouncycastlePqcCryptoRainbowRainbowKeyPairGenerator *) nil_chk(engine_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:param_];
  initialised_ = true;
}

- (JavaSecurityKeyPair *)generateKeyPair {
  if (!initialised_) {
    param_ = new_LibOrgBouncycastlePqcCryptoRainbowRainbowKeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastlePqcCryptoRainbowRainbowParameters_(random_, new_LibOrgBouncycastlePqcCryptoRainbowRainbowParameters_initWithIntArray_([new_LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_init() getVi]));
    [((LibOrgBouncycastlePqcCryptoRainbowRainbowKeyPairGenerator *) nil_chk(engine_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:param_];
    initialised_ = true;
  }
  LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *pair = [((LibOrgBouncycastlePqcCryptoRainbowRainbowKeyPairGenerator *) nil_chk(engine_)) generateKeyPair];
  LibOrgBouncycastlePqcCryptoRainbowRainbowPublicKeyParameters *pub = (LibOrgBouncycastlePqcCryptoRainbowRainbowPublicKeyParameters *) cast_chk([((LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *) nil_chk(pair)) getPublic], [LibOrgBouncycastlePqcCryptoRainbowRainbowPublicKeyParameters class]);
  LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters *priv = (LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) cast_chk([pair getPrivate], [LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters class]);
  return new_JavaSecurityKeyPair_initWithJavaSecurityPublicKey_withJavaSecurityPrivateKey_(new_LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey_initWithLibOrgBouncycastlePqcCryptoRainbowRainbowPublicKeyParameters_(pub), new_LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPrivateKey_initWithLibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters_(priv));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 2, 3, -1, -1, -1 },
    { NULL, "LJavaSecurityKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initialize__WithInt:withJavaSecuritySecureRandom:);
  methods[2].selector = @selector(initialize__WithJavaSecuritySpecAlgorithmParameterSpec:withJavaSecuritySecureRandom:);
  methods[3].selector = @selector(generateKeyPair);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "param_", "LLibOrgBouncycastlePqcCryptoRainbowRainbowKeyGenerationParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "engine_", "LLibOrgBouncycastlePqcCryptoRainbowRainbowKeyPairGenerator;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "strength_", "I", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "initialised_", "Z", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "initialize", "ILJavaSecuritySecureRandom;", "LJavaSecuritySpecAlgorithmParameterSpec;LJavaSecuritySecureRandom;", "LJavaSecurityInvalidAlgorithmParameterException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi = { "RainbowKeyPairGeneratorSpi", "lib.org.bouncycastle.pqc.jcajce.provider.rainbow", ptrTable, methods, fields, 7, 0x1, 4, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi;
}

@end

void LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi_init(LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi *self) {
  JavaSecurityKeyPairGenerator_initWithNSString_(self, @"Rainbow");
  self->engine_ = new_LibOrgBouncycastlePqcCryptoRainbowRainbowKeyPairGenerator_init();
  self->strength_ = 1024;
  self->random_ = LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom();
  self->initialised_ = false;
}

LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi *new_LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi, init)
}

LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi *create_LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi)
