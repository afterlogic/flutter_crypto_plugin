//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/Signer.java
//

#include "J2ObjC_source.h"
#include "Signer.h"

@interface LibOrgBouncycastleCryptoSigner : NSObject

@end

@implementation LibOrgBouncycastleCryptoSigner

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "V", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 2, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x401, -1, -1, 5, -1, -1, -1 },
    { NULL, "Z", 0x401, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x401, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[1].selector = @selector(updateWithByte:);
  methods[2].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[3].selector = @selector(generateSignature);
  methods[4].selector = @selector(verifySignatureWithByteArray:);
  methods[5].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "update", "B", "[BII", "LLibOrgBouncycastleCryptoCryptoException;LLibOrgBouncycastleCryptoDataLengthException;", "verifySignature", "[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoSigner = { "Signer", "lib.org.bouncycastle.crypto", ptrTable, methods, NULL, 7, 0x609, 6, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoSigner;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoSigner)
