//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/CertChainType.java
//

#include "CertChainType.h"
#include "J2ObjC_source.h"

@implementation LibOrgBouncycastleCryptoTlsCertChainType

+ (jshort)individual_certs {
  return LibOrgBouncycastleCryptoTlsCertChainType_individual_certs;
}

+ (jshort)pkipath {
  return LibOrgBouncycastleCryptoTlsCertChainType_pkipath;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsCertChainType_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jboolean)isValidWithShort:(jshort)certChainType {
  return LibOrgBouncycastleCryptoTlsCertChainType_isValidWithShort_(certChainType);
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
    { "individual_certs", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsCertChainType_individual_certs, 0x19, -1, -1, -1, -1 },
    { "pkipath", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsCertChainType_pkipath, 0x19, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "isValid", "S" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsCertChainType = { "CertChainType", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 2, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsCertChainType;
}

@end

void LibOrgBouncycastleCryptoTlsCertChainType_init(LibOrgBouncycastleCryptoTlsCertChainType *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoTlsCertChainType *new_LibOrgBouncycastleCryptoTlsCertChainType_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsCertChainType, init)
}

LibOrgBouncycastleCryptoTlsCertChainType *create_LibOrgBouncycastleCryptoTlsCertChainType_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsCertChainType, init)
}

jboolean LibOrgBouncycastleCryptoTlsCertChainType_isValidWithShort_(jshort certChainType) {
  LibOrgBouncycastleCryptoTlsCertChainType_initialize();
  return certChainType >= LibOrgBouncycastleCryptoTlsCertChainType_individual_certs && certChainType <= LibOrgBouncycastleCryptoTlsCertChainType_pkipath;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsCertChainType)
