//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/gcm/GCMMultiplier.java
//

#include "GCMMultiplier.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleCryptoModesGcmGCMMultiplier : NSObject

@end

@implementation LibOrgBouncycastleCryptoModesGcmGCMMultiplier

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "V", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 2, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init__WithByteArray:);
  methods[1].selector = @selector(multiplyHWithByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "init", "[B", "multiplyH" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoModesGcmGCMMultiplier = { "GCMMultiplier", "lib.org.bouncycastle.crypto.modes.gcm", ptrTable, methods, NULL, 7, 0x609, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoModesGcmGCMMultiplier;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoModesGcmGCMMultiplier)
