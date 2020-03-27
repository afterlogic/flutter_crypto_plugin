//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/DSA.java
//

#include "DSA.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleCryptoDSA : NSObject

@end

@implementation LibOrgBouncycastleCryptoDSA

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "V", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "[LJavaMathBigInteger;", 0x401, 2, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x401, 4, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[1].selector = @selector(generateSignatureWithByteArray:);
  methods[2].selector = @selector(verifySignatureWithByteArray:withJavaMathBigInteger:withJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "generateSignature", "[B", "verifySignature", "[BLJavaMathBigInteger;LJavaMathBigInteger;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoDSA = { "DSA", "lib.org.bouncycastle.crypto", ptrTable, methods, NULL, 7, 0x609, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoDSA;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoDSA)
