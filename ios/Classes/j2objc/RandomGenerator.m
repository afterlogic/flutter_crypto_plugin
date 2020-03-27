//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/prng/RandomGenerator.java
//

#include "J2ObjC_source.h"
#include "RandomGenerator.h"

@interface LibOrgBouncycastleCryptoPrngRandomGenerator : NSObject

@end

@implementation LibOrgBouncycastleCryptoPrngRandomGenerator

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "V", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 0, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 3, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 3, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(addSeedMaterialWithByteArray:);
  methods[1].selector = @selector(addSeedMaterialWithLong:);
  methods[2].selector = @selector(nextBytesWithByteArray:);
  methods[3].selector = @selector(nextBytesWithByteArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "addSeedMaterial", "[B", "J", "nextBytes", "[BII" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoPrngRandomGenerator = { "RandomGenerator", "lib.org.bouncycastle.crypto.prng", ptrTable, methods, NULL, 7, 0x609, 4, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoPrngRandomGenerator;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoPrngRandomGenerator)
