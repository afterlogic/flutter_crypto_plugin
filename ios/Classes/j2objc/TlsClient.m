//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsClient.java
//

#include "J2ObjC_source.h"
#include "TlsClient.h"

@interface LibOrgBouncycastleCryptoTlsTlsClient : NSObject

@end

@implementation LibOrgBouncycastleCryptoTlsTlsClient

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "V", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsSession;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsProtocolVersion;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsProtocolVersion;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "[I", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "[S", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilHashtable;", 0x401, -1, -1, 2, -1, -1, -1 },
    { NULL, "V", 0x401, 3, 4, 2, -1, -1, -1 },
    { NULL, "V", 0x401, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 9, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 11, 12, 2, -1, -1, -1 },
    { NULL, "V", 0x401, 13, 14, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsKeyExchange;", 0x401, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsAuthentication;", 0x401, -1, -1, 2, -1, -1, -1 },
    { NULL, "LJavaUtilVector;", 0x401, -1, -1, 2, -1, -1, -1 },
    { NULL, "V", 0x401, 15, 16, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init__WithLibOrgBouncycastleCryptoTlsTlsClientContext:);
  methods[1].selector = @selector(getSessionToResume);
  methods[2].selector = @selector(getClientHelloRecordLayerVersion);
  methods[3].selector = @selector(getClientVersion);
  methods[4].selector = @selector(isFallback);
  methods[5].selector = @selector(getCipherSuites);
  methods[6].selector = @selector(getCompressionMethods);
  methods[7].selector = @selector(getClientExtensions);
  methods[8].selector = @selector(notifyServerVersionWithLibOrgBouncycastleCryptoTlsProtocolVersion:);
  methods[9].selector = @selector(notifySessionIDWithByteArray:);
  methods[10].selector = @selector(notifySelectedCipherSuiteWithInt:);
  methods[11].selector = @selector(notifySelectedCompressionMethodWithShort:);
  methods[12].selector = @selector(processServerExtensionsWithJavaUtilHashtable:);
  methods[13].selector = @selector(processServerSupplementalDataWithJavaUtilVector:);
  methods[14].selector = @selector(getKeyExchange);
  methods[15].selector = @selector(getAuthentication);
  methods[16].selector = @selector(getClientSupplementalData);
  methods[17].selector = @selector(notifyNewSessionTicketWithLibOrgBouncycastleCryptoTlsNewSessionTicket:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoTlsTlsClientContext;", "LJavaIoIOException;", "notifyServerVersion", "LLibOrgBouncycastleCryptoTlsProtocolVersion;", "notifySessionID", "[B", "notifySelectedCipherSuite", "I", "notifySelectedCompressionMethod", "S", "processServerExtensions", "LJavaUtilHashtable;", "processServerSupplementalData", "LJavaUtilVector;", "notifyNewSessionTicket", "LLibOrgBouncycastleCryptoTlsNewSessionTicket;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsTlsClient = { "TlsClient", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, NULL, 7, 0x609, 18, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsTlsClient;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsTlsClient)