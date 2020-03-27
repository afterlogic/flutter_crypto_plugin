//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/AlertLevel.java
//

#include "AlertLevel.h"
#include "J2ObjC_source.h"

@implementation LibOrgBouncycastleCryptoTlsAlertLevel

+ (jshort)warning {
  return LibOrgBouncycastleCryptoTlsAlertLevel_warning;
}

+ (jshort)fatal {
  return LibOrgBouncycastleCryptoTlsAlertLevel_fatal;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsAlertLevel_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (NSString *)getNameWithShort:(jshort)alertDescription {
  return LibOrgBouncycastleCryptoTlsAlertLevel_getNameWithShort_(alertDescription);
}

+ (NSString *)getTextWithShort:(jshort)alertDescription {
  return LibOrgBouncycastleCryptoTlsAlertLevel_getTextWithShort_(alertDescription);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x9, 2, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getNameWithShort:);
  methods[2].selector = @selector(getTextWithShort:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "warning", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsAlertLevel_warning, 0x19, -1, -1, -1, -1 },
    { "fatal", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsAlertLevel_fatal, 0x19, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getName", "S", "getText" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsAlertLevel = { "AlertLevel", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 3, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsAlertLevel;
}

@end

void LibOrgBouncycastleCryptoTlsAlertLevel_init(LibOrgBouncycastleCryptoTlsAlertLevel *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoTlsAlertLevel *new_LibOrgBouncycastleCryptoTlsAlertLevel_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsAlertLevel, init)
}

LibOrgBouncycastleCryptoTlsAlertLevel *create_LibOrgBouncycastleCryptoTlsAlertLevel_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsAlertLevel, init)
}

NSString *LibOrgBouncycastleCryptoTlsAlertLevel_getNameWithShort_(jshort alertDescription) {
  LibOrgBouncycastleCryptoTlsAlertLevel_initialize();
  switch (alertDescription) {
    case LibOrgBouncycastleCryptoTlsAlertLevel_warning:
    return @"warning";
    case LibOrgBouncycastleCryptoTlsAlertLevel_fatal:
    return @"fatal";
    default:
    return @"UNKNOWN";
  }
}

NSString *LibOrgBouncycastleCryptoTlsAlertLevel_getTextWithShort_(jshort alertDescription) {
  LibOrgBouncycastleCryptoTlsAlertLevel_initialize();
  return JreStrcat("$CSC", LibOrgBouncycastleCryptoTlsAlertLevel_getNameWithShort_(alertDescription), '(', alertDescription, ')');
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsAlertLevel)
