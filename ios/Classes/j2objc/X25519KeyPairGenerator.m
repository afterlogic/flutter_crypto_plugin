//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/X25519KeyPairGenerator.java
//

#include "AsymmetricCipherKeyPair.h"
#include "J2ObjC_source.h"
#include "KeyGenerationParameters.h"
#include "X25519KeyPairGenerator.h"
#include "X25519PrivateKeyParameters.h"
#include "X25519PublicKeyParameters.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator () {
 @public
  JavaSecuritySecureRandom *random_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator, random_, JavaSecuritySecureRandom *)

@implementation LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)parameters {
  self->random_ = [((LibOrgBouncycastleCryptoKeyGenerationParameters *) nil_chk(parameters)) getRandom];
}

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair {
  LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *privateKey = new_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaSecuritySecureRandom_(random_);
  LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters *publicKey = [privateKey generatePublicKey];
  return new_LibOrgBouncycastleCryptoAsymmetricCipherKeyPair_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(publicKey, privateKey);
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
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoKeyGenerationParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator = { "X25519KeyPairGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator;
}

@end

void LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator_init(LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator *new_LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator, init)
}

LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator *create_LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsX25519KeyPairGenerator)
