//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/ec/ECDecryptor.java
//

#include "ECDecryptor.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleCryptoEcECDecryptor : NSObject

@end

@implementation LibOrgBouncycastleCryptoEcECDecryptor

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "V", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x401, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init__WithLibOrgBouncycastleCryptoCipherParameters:);
  methods[1].selector = @selector(decryptWithLibOrgBouncycastleCryptoEcECPair:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoCipherParameters;", "decrypt", "LLibOrgBouncycastleCryptoEcECPair;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEcECDecryptor = { "ECDecryptor", "lib.org.bouncycastle.crypto.ec", ptrTable, methods, NULL, 7, 0x609, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEcECDecryptor;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEcECDecryptor)
