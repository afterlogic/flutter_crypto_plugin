//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/newhope/NHKeyPairGenerator.java
//

#include "AsymmetricCipherKeyPair.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyGenerationParameters.h"
#include "NHKeyPairGenerator.h"
#include "NHPrivateKeyParameters.h"
#include "NHPublicKeyParameters.h"
#include "NewHope.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator () {
 @public
  JavaSecuritySecureRandom *random_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator, random_, JavaSecuritySecureRandom *)

@implementation LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param {
  self->random_ = [((LibOrgBouncycastleCryptoKeyGenerationParameters *) nil_chk(param)) getRandom];
}

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair {
  IOSByteArray *pubData = [IOSByteArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeNewHope_SENDA_BYTES];
  IOSShortArray *secData = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeNewHope_POLY_SIZE];
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_keygenWithJavaSecuritySecureRandom_withByteArray_withShortArray_(random_, pubData, secData);
  return new_LibOrgBouncycastleCryptoAsymmetricCipherKeyPair_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(new_LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters_initWithByteArray_(pubData), new_LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters_initWithShortArray_(secData));
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
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator = { "NHKeyPairGenerator", "lib.org.bouncycastle.pqc.crypto.newhope", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator;
}

@end

void LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator_init(LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator *self) {
  NSObject_init(self);
}

LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator *new_LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator, init)
}

LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator *create_LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoNewhopeNHKeyPairGenerator)
