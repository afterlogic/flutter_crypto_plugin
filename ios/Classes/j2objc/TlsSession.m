//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsSession.java
//

#include "J2ObjC_source.h"
#include "TlsSession.h"

@interface LibOrgBouncycastleCryptoTlsTlsSession : NSObject

@end

@implementation LibOrgBouncycastleCryptoTlsTlsSession

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleCryptoTlsSessionParameters;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x401, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(exportSessionParameters);
  methods[1].selector = @selector(getSessionID);
  methods[2].selector = @selector(invalidate);
  methods[3].selector = @selector(isResumable);
  #pragma clang diagnostic pop
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsTlsSession = { "TlsSession", "lib.org.bouncycastle.crypto.tls", NULL, methods, NULL, 7, 0x609, 4, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsTlsSession;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsTlsSession)
