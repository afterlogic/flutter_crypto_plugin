//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/X25519Agreement.java
//

#include "CipherParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "X25519Agreement.h"
#include "X25519PrivateKeyParameters.h"
#include "X25519PublicKeyParameters.h"

@interface LibOrgBouncycastleCryptoAgreementX25519Agreement () {
 @public
  LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *privateKey_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoAgreementX25519Agreement, privateKey_, LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *)

@implementation LibOrgBouncycastleCryptoAgreementX25519Agreement

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoAgreementX25519Agreement_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters {
  self->privateKey_ = (LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *) cast_chk(parameters, [LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters class]);
}

- (jint)getAgreementSize {
  return LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_SECRET_SIZE;
}

- (void)calculateAgreementWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)publicKey
                                                         withByteArray:(IOSByteArray *)buf
                                                               withInt:(jint)off {
  [((LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *) nil_chk(privateKey_)) generateSecretWithLibOrgBouncycastleCryptoParamsX25519PublicKeyParameters:(LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters *) cast_chk(publicKey, [LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters class]) withByteArray:buf withInt:off];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getAgreementSize);
  methods[3].selector = @selector(calculateAgreementWithLibOrgBouncycastleCryptoCipherParameters:withByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "privateKey_", "LLibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoCipherParameters;", "calculateAgreement", "LLibOrgBouncycastleCryptoCipherParameters;[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoAgreementX25519Agreement = { "X25519Agreement", "lib.org.bouncycastle.crypto.agreement", ptrTable, methods, fields, 7, 0x11, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoAgreementX25519Agreement;
}

@end

void LibOrgBouncycastleCryptoAgreementX25519Agreement_init(LibOrgBouncycastleCryptoAgreementX25519Agreement *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoAgreementX25519Agreement *new_LibOrgBouncycastleCryptoAgreementX25519Agreement_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoAgreementX25519Agreement, init)
}

LibOrgBouncycastleCryptoAgreementX25519Agreement *create_LibOrgBouncycastleCryptoAgreementX25519Agreement_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoAgreementX25519Agreement, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoAgreementX25519Agreement)