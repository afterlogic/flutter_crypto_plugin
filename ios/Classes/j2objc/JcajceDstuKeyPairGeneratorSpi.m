//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/dstu/JcajceDstuKeyPairGeneratorSpi.java
//

#include "ASN1ObjectIdentifier.h"
#include "AsymmetricCipherKeyPair.h"
#include "AsymmetricKeyParameter.h"
#include "BCDSTU4145PrivateKey.h"
#include "BCDSTU4145PublicKey.h"
#include "BouncyCastleProvider.h"
#include "DSTU4145KeyPairGenerator.h"
#include "DSTU4145NamedCurves.h"
#include "DSTU4145ParameterSpec.h"
#include "DSTU4145Parameters.h"
#include "EC5Util.h"
#include "ECCurve.h"
#include "ECDomainParameters.h"
#include "ECKeyGenerationParameters.h"
#include "ECKeyPairGenerator.h"
#include "ECNamedCurveGenParameterSpec.h"
#include "ECNamedCurveSpec.h"
#include "ECParameterSpec.h"
#include "ECPoint.h"
#include "ECPrivateKeyParameters.h"
#include "ECPublicKeyParameters.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcajceDstuKeyPairGeneratorSpi.h"
#include "ProviderConfiguration.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"
#include "java/security/InvalidAlgorithmParameterException.h"
#include "java/security/InvalidParameterException.h"
#include "java/security/KeyPair.h"
#include "java/security/KeyPairGenerator.h"
#include "java/security/SecureRandom.h"
#include "java/security/spec/AlgorithmParameterSpec.h"
#include "java/security/spec/ECGenParameterSpec.h"
#include "java/security/spec/ECParameterSpec.h"
#include "java/security/spec/ECPoint.h"
#include "java/security/spec/EllipticCurve.h"

@implementation LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)initialize__WithInt:(jint)strength
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  self->random_ = random;
  if (ecParams_ != nil) {
    @try {
      [self initialize__WithJavaSecuritySpecAlgorithmParameterSpec:(JavaSecuritySpecECGenParameterSpec *) cast_chk(ecParams_, [JavaSecuritySpecECGenParameterSpec class]) withJavaSecuritySecureRandom:random];
    }
    @catch (JavaSecurityInvalidAlgorithmParameterException *e) {
      @throw new_JavaSecurityInvalidParameterException_initWithNSString_(@"key size not configurable.");
    }
  }
  else {
    @throw new_JavaSecurityInvalidParameterException_initWithNSString_(@"unknown key size.");
  }
}

- (void)initialize__WithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
                                  withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  if ([params isKindOfClass:[LibOrgBouncycastleJceSpecECParameterSpec class]]) {
    LibOrgBouncycastleJceSpecECParameterSpec *p = (LibOrgBouncycastleJceSpecECParameterSpec *) params;
    self->ecParams_ = params;
    param_ = new_LibOrgBouncycastleCryptoParamsECKeyGenerationParameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_(new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleJceSpecECParameterSpec *) nil_chk(p)) getCurve], [p getG], [p getN], [p getH]), random);
    [((LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *) nil_chk(engine_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:param_];
    initialised_ = true;
  }
  else if ([params isKindOfClass:[JavaSecuritySpecECParameterSpec class]]) {
    JavaSecuritySpecECParameterSpec *p = (JavaSecuritySpecECParameterSpec *) params;
    self->ecParams_ = params;
    LibOrgBouncycastleMathEcECCurve *curve = LibOrgBouncycastleJcajceProviderAsymmetricUtilEC5Util_convertCurveWithJavaSecuritySpecEllipticCurve_([((JavaSecuritySpecECParameterSpec *) nil_chk(p)) getCurve]);
    LibOrgBouncycastleMathEcECPoint *g = LibOrgBouncycastleJcajceProviderAsymmetricUtilEC5Util_convertPointWithLibOrgBouncycastleMathEcECCurve_withJavaSecuritySpecECPoint_withBoolean_(curve, [p getGenerator], false);
    if ([p isKindOfClass:[LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec class]]) {
      LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *dstuSpec = (LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *) p;
      param_ = new_LibOrgBouncycastleCryptoParamsECKeyGenerationParameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_(new_LibOrgBouncycastleCryptoParamsDSTU4145Parameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withByteArray_(new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(curve, g, [p getOrder], JavaMathBigInteger_valueOfWithLong_([p getCofactor])), [dstuSpec getDKE]), random);
    }
    else {
      param_ = new_LibOrgBouncycastleCryptoParamsECKeyGenerationParameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_(new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(curve, g, [p getOrder], JavaMathBigInteger_valueOfWithLong_([p getCofactor])), random);
    }
    [((LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *) nil_chk(engine_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:param_];
    initialised_ = true;
  }
  else if ([params isKindOfClass:[JavaSecuritySpecECGenParameterSpec class]] || [params isKindOfClass:[LibOrgBouncycastleJceSpecECNamedCurveGenParameterSpec class]]) {
    NSString *curveName;
    if ([params isKindOfClass:[JavaSecuritySpecECGenParameterSpec class]]) {
      curveName = [((JavaSecuritySpecECGenParameterSpec *) nil_chk(((JavaSecuritySpecECGenParameterSpec *) params))) getName];
    }
    else {
      curveName = [((LibOrgBouncycastleJceSpecECNamedCurveGenParameterSpec *) nil_chk(((LibOrgBouncycastleJceSpecECNamedCurveGenParameterSpec *) cast_chk(params, [LibOrgBouncycastleJceSpecECNamedCurveGenParameterSpec class])))) getName];
    }
    LibOrgBouncycastleCryptoParamsECDomainParameters *ecP = LibOrgBouncycastleAsn1UaDSTU4145NamedCurves_getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(curveName));
    if (ecP == nil) {
      @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_(JreStrcat("$$", @"unknown curve name: ", curveName));
    }
    self->ecParams_ = new_LibOrgBouncycastleJceSpecECNamedCurveSpec_initWithNSString_withLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(curveName, [ecP getCurve], [ecP getG], [ecP getN], [ecP getH], [ecP getSeed]);
    JavaSecuritySpecECParameterSpec *p = (JavaSecuritySpecECParameterSpec *) cast_chk(ecParams_, [JavaSecuritySpecECParameterSpec class]);
    LibOrgBouncycastleMathEcECCurve *curve = LibOrgBouncycastleJcajceProviderAsymmetricUtilEC5Util_convertCurveWithJavaSecuritySpecEllipticCurve_([p getCurve]);
    LibOrgBouncycastleMathEcECPoint *g = LibOrgBouncycastleJcajceProviderAsymmetricUtilEC5Util_convertPointWithLibOrgBouncycastleMathEcECCurve_withJavaSecuritySpecECPoint_withBoolean_(curve, [p getGenerator], false);
    param_ = new_LibOrgBouncycastleCryptoParamsECKeyGenerationParameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_(new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(curve, g, [p getOrder], JavaMathBigInteger_valueOfWithLong_([p getCofactor])), random);
    [((LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *) nil_chk(engine_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:param_];
    initialised_ = true;
  }
  else if (params == nil && [((id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration>) nil_chk(JreLoadStatic(LibOrgBouncycastleJceProviderBouncyCastleProvider, CONFIGURATION))) getEcImplicitlyCa] != nil) {
    LibOrgBouncycastleJceSpecECParameterSpec *p = [((id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration>) nil_chk(JreLoadStatic(LibOrgBouncycastleJceProviderBouncyCastleProvider, CONFIGURATION))) getEcImplicitlyCa];
    self->ecParams_ = params;
    param_ = new_LibOrgBouncycastleCryptoParamsECKeyGenerationParameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_(new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleJceSpecECParameterSpec *) nil_chk(p)) getCurve], [p getG], [p getN], [p getH]), random);
    [((LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *) nil_chk(engine_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:param_];
    initialised_ = true;
  }
  else if (params == nil && [((id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration>) nil_chk(JreLoadStatic(LibOrgBouncycastleJceProviderBouncyCastleProvider, CONFIGURATION))) getEcImplicitlyCa] == nil) {
    @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_(@"null parameter passed but no implicitCA set");
  }
  else {
    @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_(JreStrcat("$$", @"parameter object not a ECParameterSpec: ", [[((id<JavaSecuritySpecAlgorithmParameterSpec>) nil_chk(params)) java_getClass] getName]));
  }
}

- (JavaSecurityKeyPair *)generateKeyPair {
  if (!initialised_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"DSTU Key Pair Generator not initialised");
  }
  LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *pair = [((LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *) nil_chk(engine_)) generateKeyPair];
  LibOrgBouncycastleCryptoParamsECPublicKeyParameters *pub = (LibOrgBouncycastleCryptoParamsECPublicKeyParameters *) cast_chk([((LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *) nil_chk(pair)) getPublic], [LibOrgBouncycastleCryptoParamsECPublicKeyParameters class]);
  LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *priv = (LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) cast_chk([pair getPrivate], [LibOrgBouncycastleCryptoParamsECPrivateKeyParameters class]);
  if ([ecParams_ isKindOfClass:[LibOrgBouncycastleJceSpecECParameterSpec class]]) {
    LibOrgBouncycastleJceSpecECParameterSpec *p = (LibOrgBouncycastleJceSpecECParameterSpec *) ecParams_;
    LibOrgBouncycastleJcajceProviderAsymmetricDstuBCDSTU4145PublicKey *pubKey = new_LibOrgBouncycastleJcajceProviderAsymmetricDstuBCDSTU4145PublicKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPublicKeyParameters_withLibOrgBouncycastleJceSpecECParameterSpec_(algorithm_JcajceDstuKeyPairGeneratorSpi_, pub, p);
    return new_JavaSecurityKeyPair_initWithJavaSecurityPublicKey_withJavaSecurityPrivateKey_(pubKey, new_LibOrgBouncycastleJcajceProviderAsymmetricDstuBCDSTU4145PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricDstuBCDSTU4145PublicKey_withLibOrgBouncycastleJceSpecECParameterSpec_(algorithm_JcajceDstuKeyPairGeneratorSpi_, priv, pubKey, p));
  }
  else if (ecParams_ == nil) {
    return new_JavaSecurityKeyPair_initWithJavaSecurityPublicKey_withJavaSecurityPrivateKey_(new_LibOrgBouncycastleJcajceProviderAsymmetricDstuBCDSTU4145PublicKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPublicKeyParameters_(algorithm_JcajceDstuKeyPairGeneratorSpi_, pub), new_LibOrgBouncycastleJcajceProviderAsymmetricDstuBCDSTU4145PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_(algorithm_JcajceDstuKeyPairGeneratorSpi_, priv));
  }
  else {
    JavaSecuritySpecECParameterSpec *p = (JavaSecuritySpecECParameterSpec *) cast_chk(ecParams_, [JavaSecuritySpecECParameterSpec class]);
    LibOrgBouncycastleJcajceProviderAsymmetricDstuBCDSTU4145PublicKey *pubKey = new_LibOrgBouncycastleJcajceProviderAsymmetricDstuBCDSTU4145PublicKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPublicKeyParameters_withJavaSecuritySpecECParameterSpec_(algorithm_JcajceDstuKeyPairGeneratorSpi_, pub, p);
    return new_JavaSecurityKeyPair_initWithJavaSecurityPublicKey_withJavaSecurityPrivateKey_(pubKey, new_LibOrgBouncycastleJcajceProviderAsymmetricDstuBCDSTU4145PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricDstuBCDSTU4145PublicKey_withJavaSecuritySpecECParameterSpec_(algorithm_JcajceDstuKeyPairGeneratorSpi_, priv, pubKey, p));
  }
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
    { "ecParams_", "LNSObject;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "engine_", "LLibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "algorithm_JcajceDstuKeyPairGeneratorSpi_", "LNSString;", .constantValue.asLong = 0, 0x0, 4, -1, -1, -1 },
    { "param_", "LLibOrgBouncycastleCryptoParamsECKeyGenerationParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "initialised_", "Z", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "initialize", "ILJavaSecuritySecureRandom;", "LJavaSecuritySpecAlgorithmParameterSpec;LJavaSecuritySecureRandom;", "LJavaSecurityInvalidAlgorithmParameterException;", "algorithm" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi = { "JcajceDstuKeyPairGeneratorSpi", "lib.org.bouncycastle.jcajce.provider.asymmetric.dstu", ptrTable, methods, fields, 7, 0x1, 4, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi_init(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi *self) {
  JavaSecurityKeyPairGenerator_initWithNSString_(self, @"DSTU4145");
  self->ecParams_ = nil;
  self->engine_ = new_LibOrgBouncycastleCryptoGeneratorsDSTU4145KeyPairGenerator_init();
  self->algorithm_JcajceDstuKeyPairGeneratorSpi_ = @"DSTU4145";
  self->random_ = nil;
  self->initialised_ = false;
}

LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi)
