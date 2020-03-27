//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/ECBasisType.java
//

#include "ECBasisType.h"
#include "J2ObjC_source.h"

@implementation LibOrgBouncycastleCryptoTlsECBasisType

+ (jshort)ec_basis_trinomial {
  return LibOrgBouncycastleCryptoTlsECBasisType_ec_basis_trinomial;
}

+ (jshort)ec_basis_pentanomial {
  return LibOrgBouncycastleCryptoTlsECBasisType_ec_basis_pentanomial;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsECBasisType_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jboolean)isValidWithShort:(jshort)ecBasisType {
  return LibOrgBouncycastleCryptoTlsECBasisType_isValidWithShort_(ecBasisType);
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
    { "ec_basis_trinomial", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsECBasisType_ec_basis_trinomial, 0x19, -1, -1, -1, -1 },
    { "ec_basis_pentanomial", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsECBasisType_ec_basis_pentanomial, 0x19, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "isValid", "S" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsECBasisType = { "ECBasisType", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 2, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsECBasisType;
}

@end

void LibOrgBouncycastleCryptoTlsECBasisType_init(LibOrgBouncycastleCryptoTlsECBasisType *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoTlsECBasisType *new_LibOrgBouncycastleCryptoTlsECBasisType_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsECBasisType, init)
}

LibOrgBouncycastleCryptoTlsECBasisType *create_LibOrgBouncycastleCryptoTlsECBasisType_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsECBasisType, init)
}

jboolean LibOrgBouncycastleCryptoTlsECBasisType_isValidWithShort_(jshort ecBasisType) {
  LibOrgBouncycastleCryptoTlsECBasisType_initialize();
  return ecBasisType >= LibOrgBouncycastleCryptoTlsECBasisType_ec_basis_trinomial && ecBasisType <= LibOrgBouncycastleCryptoTlsECBasisType_ec_basis_pentanomial;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsECBasisType)
