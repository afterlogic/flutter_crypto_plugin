//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/util/CipherKeyGeneratorFactory.java
//

#include "ASN1ObjectIdentifier.h"
#include "AlgorithmIdentifierFactory.h"
#include "CipherKeyGenerator.h"
#include "CipherKeyGeneratorFactory.h"
#include "DESKeyGenerator.h"
#include "DESedeKeyGenerator.h"
#include "J2ObjC_source.h"
#include "KISAObjectIdentifiers.h"
#include "KeyGenerationParameters.h"
#include "NISTObjectIdentifiers.h"
#include "NTTObjectIdentifiers.h"
#include "OIWObjectIdentifiers.h"
#include "PKCSObjectIdentifiers.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory ()

- (instancetype)init;

+ (LibOrgBouncycastleCryptoCipherKeyGenerator *)createCipherKeyGeneratorWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                                                                                             withInt:(jint)keySize;

@end

__attribute__((unused)) static void LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_init(LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory *self);

__attribute__((unused)) static LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory *new_LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory *create_LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_init(void);

__attribute__((unused)) static LibOrgBouncycastleCryptoCipherKeyGenerator *LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createCipherKeyGeneratorWithJavaSecuritySecureRandom_withInt_(JavaSecuritySecureRandom *random, jint keySize);

@implementation LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleCryptoCipherKeyGenerator *)createKeyGeneratorWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)algorithm
                                                                                    withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createKeyGeneratorWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaSecuritySecureRandom_(algorithm, random);
}

+ (LibOrgBouncycastleCryptoCipherKeyGenerator *)createCipherKeyGeneratorWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                                                                                             withInt:(jint)keySize {
  return LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createCipherKeyGeneratorWithJavaSecuritySecureRandom_withInt_(random, keySize);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherKeyGenerator;", 0x9, 0, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherKeyGenerator;", 0xa, 3, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(createKeyGeneratorWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withJavaSecuritySecureRandom:);
  methods[2].selector = @selector(createCipherKeyGeneratorWithJavaSecuritySecureRandom:withInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "createKeyGenerator", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LJavaSecuritySecureRandom;", "LJavaLangIllegalArgumentException;", "createCipherKeyGenerator", "LJavaSecuritySecureRandom;I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory = { "CipherKeyGeneratorFactory", "lib.org.bouncycastle.crypto.util", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory;
}

@end

void LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_init(LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory *new_LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory, init)
}

LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory *create_LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory, init)
}

LibOrgBouncycastleCryptoCipherKeyGenerator *LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createKeyGeneratorWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaSecuritySecureRandom_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *algorithm, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_initialize();
  if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_aes128_CBC))) isEqual:algorithm]) {
    return LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createCipherKeyGeneratorWithJavaSecuritySecureRandom_withInt_(random, 128);
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_aes192_CBC))) isEqual:algorithm]) {
    return LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createCipherKeyGeneratorWithJavaSecuritySecureRandom_withInt_(random, 192);
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_aes256_CBC))) isEqual:algorithm]) {
    return LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createCipherKeyGeneratorWithJavaSecuritySecureRandom_withInt_(random, 256);
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, des_EDE3_CBC))) isEqual:algorithm]) {
    LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator *keyGen = new_LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator_init();
    [keyGen init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:new_LibOrgBouncycastleCryptoKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_(random, 192)];
    return keyGen;
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NttNTTObjectIdentifiers, id_camellia128_cbc))) isEqual:algorithm]) {
    return LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createCipherKeyGeneratorWithJavaSecuritySecureRandom_withInt_(random, 128);
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NttNTTObjectIdentifiers, id_camellia192_cbc))) isEqual:algorithm]) {
    return LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createCipherKeyGeneratorWithJavaSecuritySecureRandom_withInt_(random, 192);
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NttNTTObjectIdentifiers, id_camellia256_cbc))) isEqual:algorithm]) {
    return LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createCipherKeyGeneratorWithJavaSecuritySecureRandom_withInt_(random, 256);
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1KisaKISAObjectIdentifiers, id_seedCBC))) isEqual:algorithm]) {
    return LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createCipherKeyGeneratorWithJavaSecuritySecureRandom_withInt_(random, 128);
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory, CAST5_CBC))) isEqual:algorithm]) {
    return LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createCipherKeyGeneratorWithJavaSecuritySecureRandom_withInt_(random, 128);
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1OiwOIWObjectIdentifiers, desCBC))) isEqual:algorithm]) {
    LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator *keyGen = new_LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator_init();
    [keyGen init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:new_LibOrgBouncycastleCryptoKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_(random, 64)];
    return keyGen;
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, rc4))) isEqual:algorithm]) {
    return LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createCipherKeyGeneratorWithJavaSecuritySecureRandom_withInt_(random, 128);
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, RC2_CBC))) isEqual:algorithm]) {
    return LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createCipherKeyGeneratorWithJavaSecuritySecureRandom_withInt_(random, 128);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"cannot recognise cipher: ", algorithm));
  }
}

LibOrgBouncycastleCryptoCipherKeyGenerator *LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_createCipherKeyGeneratorWithJavaSecuritySecureRandom_withInt_(JavaSecuritySecureRandom *random, jint keySize) {
  LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory_initialize();
  LibOrgBouncycastleCryptoCipherKeyGenerator *keyGen = new_LibOrgBouncycastleCryptoCipherKeyGenerator_init();
  [keyGen init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:new_LibOrgBouncycastleCryptoKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_(random, keySize)];
  return keyGen;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoUtilCipherKeyGeneratorFactory)