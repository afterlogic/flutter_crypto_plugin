//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/SupplementalDataType.java
//

#include "J2ObjC_source.h"
#include "SupplementalDataType.h"

@implementation LibOrgBouncycastleCryptoTlsSupplementalDataType

+ (jint)user_mapping_data {
  return LibOrgBouncycastleCryptoTlsSupplementalDataType_user_mapping_data;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsSupplementalDataType_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "user_mapping_data", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsSupplementalDataType_user_mapping_data, 0x19, -1, -1, -1, -1 },
  };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsSupplementalDataType = { "SupplementalDataType", "lib.org.bouncycastle.crypto.tls", NULL, methods, fields, 7, 0x1, 1, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsSupplementalDataType;
}

@end

void LibOrgBouncycastleCryptoTlsSupplementalDataType_init(LibOrgBouncycastleCryptoTlsSupplementalDataType *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoTlsSupplementalDataType *new_LibOrgBouncycastleCryptoTlsSupplementalDataType_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsSupplementalDataType, init)
}

LibOrgBouncycastleCryptoTlsSupplementalDataType *create_LibOrgBouncycastleCryptoTlsSupplementalDataType_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsSupplementalDataType, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsSupplementalDataType)
