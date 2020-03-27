//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/KDF1BytesGenerator.java
//

#include "BaseKDFBytesGenerator.h"
#include "Digest.h"
#include "J2ObjC_source.h"
#include "KDF1BytesGenerator.h"

@implementation LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator

- (instancetype)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest {
  LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator_initWithLibOrgBouncycastleCryptoDigest_(self, digest);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoDigest:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigest;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator = { "KDF1BytesGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator;
}

@end

void LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator_initWithLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator *self, id<LibOrgBouncycastleCryptoDigest> digest) {
  LibOrgBouncycastleCryptoGeneratorsBaseKDFBytesGenerator_initWithInt_withLibOrgBouncycastleCryptoDigest_(self, 0, digest);
}

LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator *new_LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator, initWithLibOrgBouncycastleCryptoDigest_, digest)
}

LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator *create_LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator, initWithLibOrgBouncycastleCryptoDigest_, digest)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator)
