//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/HeartbeatMessageType.java
//

#include "HeartbeatMessageType.h"
#include "J2ObjC_source.h"

@implementation LibOrgBouncycastleCryptoTlsHeartbeatMessageType

+ (jshort)heartbeat_request {
  return LibOrgBouncycastleCryptoTlsHeartbeatMessageType_heartbeat_request;
}

+ (jshort)heartbeat_response {
  return LibOrgBouncycastleCryptoTlsHeartbeatMessageType_heartbeat_response;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsHeartbeatMessageType_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jboolean)isValidWithShort:(jshort)heartbeatMessageType {
  return LibOrgBouncycastleCryptoTlsHeartbeatMessageType_isValidWithShort_(heartbeatMessageType);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(isValidWithShort:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "heartbeat_request", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsHeartbeatMessageType_heartbeat_request, 0x19, -1, -1, -1, -1 },
    { "heartbeat_response", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsHeartbeatMessageType_heartbeat_response, 0x19, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "isValid", "S" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsHeartbeatMessageType = { "HeartbeatMessageType", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 2, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsHeartbeatMessageType;
}

@end

void LibOrgBouncycastleCryptoTlsHeartbeatMessageType_init(LibOrgBouncycastleCryptoTlsHeartbeatMessageType *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoTlsHeartbeatMessageType *new_LibOrgBouncycastleCryptoTlsHeartbeatMessageType_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsHeartbeatMessageType, init)
}

LibOrgBouncycastleCryptoTlsHeartbeatMessageType *create_LibOrgBouncycastleCryptoTlsHeartbeatMessageType_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsHeartbeatMessageType, init)
}

jboolean LibOrgBouncycastleCryptoTlsHeartbeatMessageType_isValidWithShort_(jshort heartbeatMessageType) {
  LibOrgBouncycastleCryptoTlsHeartbeatMessageType_initialize();
  return heartbeatMessageType >= LibOrgBouncycastleCryptoTlsHeartbeatMessageType_heartbeat_request && heartbeatMessageType <= LibOrgBouncycastleCryptoTlsHeartbeatMessageType_heartbeat_response;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsHeartbeatMessageType)