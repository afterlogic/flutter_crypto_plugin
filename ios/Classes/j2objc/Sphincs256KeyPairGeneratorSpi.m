//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/sphincs/Sphincs256KeyPairGeneratorSpi.java
//

#include "ASN1ObjectIdentifier.h"
#include "AsymmetricCipherKeyPair.h"
#include "AsymmetricKeyParameter.h"
#include "BCSphincs256PrivateKey.h"
#include "BCSphincs256PublicKey.h"
#include "CryptoServicesRegistrar.h"
#include "J2ObjC_source.h"
#include "NISTObjectIdentifiers.h"
#include "SHA3Digest.h"
#include "SHA512tDigest.h"
#include "SPHINCS256KeyGenParameterSpec.h"
#include "SPHINCS256KeyGenerationParameters.h"
#include "SPHINCS256KeyPairGenerator.h"
#include "SPHINCSPrivateKeyParameters.h"
#include "SPHINCSPublicKeyParameters.h"
#include "Sphincs256KeyPairGeneratorSpi.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/security/InvalidAlgorithmParameterException.h"
#include "java/security/KeyPair.h"
#include "java/security/KeyPairGenerator.h"
#include "java/security/SecureRandom.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@implementation LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyPairGeneratorSpi

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyPairGeneratorSpi_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)initialize__WithInt:(jint)strength
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"use AlgorithmParameterSpec");
}

- (void)initialize__WithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
                                  withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  if (!([params isKindOfClass:[LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec class]])) {
    @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_(@"parameter object not a SPHINCS256KeyGenParameterSpec");
  }
  LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec *sphincsParams = (LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec *) cast_chk(params, [LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec class]);
  if ([((NSString *) nil_chk([((LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec *) nil_chk(sphincsParams)) getTreeDigest])) isEqual:LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec_SHA512_256]) {
    treeDigest_ = JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512_256);
    param_ = new_LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoDigest_(random, new_LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithInt_(256));
  }
  else if ([((NSString *) nil_chk([sphincsParams getTreeDigest])) isEqual:LibOrgBouncycastlePqcJcajceSpecSPHINCS256KeyGenParameterSpec_SHA3_256]) {
    treeDigest_ = JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_256);
    param_ = new_LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoDigest_(random, new_LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithInt_(256));
  }
  [((LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyPairGenerator *) nil_chk(engine_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:param_];
  initialised_ = true;
}

- (JavaSecurityKeyPair *)generateKeyPair {
  if (!initialised_) {
    param_ = new_LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoDigest_(random_, new_LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithInt_(256));
    [((LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyPairGenerator *) nil_chk(engine_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:param_];
    initialised_ = true;
  }
  LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *pair = [((LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyPairGenerator *) nil_chk(engine_)) generateKeyPair];
  LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters *pub = (LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters *) cast_chk([((LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *) nil_chk(pair)) getPublic], [LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters class]);
  LibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters *priv = (LibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters *) cast_chk([pair getPrivate], [LibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters class]);
  return new_JavaSecurityKeyPair_initWithJavaSecurityPublicKey_withJavaSecurityPrivateKey_(new_LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters_(treeDigest_, pub), new_LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters_(treeDigest_, priv));
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
    { "treeDigest_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "param_", "LLibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "engine_", "LLibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyPairGenerator;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "initialised_", "Z", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "initialize", "ILJavaSecuritySecureRandom;", "LJavaSecuritySpecAlgorithmParameterSpec;LJavaSecuritySecureRandom;", "LJavaSecurityInvalidAlgorithmParameterException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyPairGeneratorSpi = { "Sphincs256KeyPairGeneratorSpi", "lib.org.bouncycastle.pqc.jcajce.provider.sphincs", ptrTable, methods, fields, 7, 0x1, 4, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyPairGeneratorSpi;
}

@end

void LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyPairGeneratorSpi_init(LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyPairGeneratorSpi *self) {
  JavaSecurityKeyPairGenerator_initWithNSString_(self, @"SPHINCS256");
  self->treeDigest_ = JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512_256);
  self->engine_ = new_LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyPairGenerator_init();
  self->random_ = LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom();
  self->initialised_ = false;
}

LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyPairGeneratorSpi *new_LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyPairGeneratorSpi_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyPairGeneratorSpi, init)
}

LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyPairGeneratorSpi *create_LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyPairGeneratorSpi_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyPairGeneratorSpi, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyPairGeneratorSpi)