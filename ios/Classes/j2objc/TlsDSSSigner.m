//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsDSSSigner.java
//

#include "AsymmetricKeyParameter.h"
#include "DSA.h"
#include "DSAPublicKeyParameters.h"
#include "DSASigner.h"
#include "Digest.h"
#include "HMacDSAKCalculator.h"
#include "J2ObjC_source.h"
#include "SignatureAlgorithm.h"
#include "TlsDSASigner.h"
#include "TlsDSSSigner.h"
#include "TlsUtils.h"

@implementation LibOrgBouncycastleCryptoTlsTlsDSSSigner

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsTlsDSSSigner_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jboolean)isValidPublicKeyWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicKey {
  return [publicKey isKindOfClass:[LibOrgBouncycastleCryptoParamsDSAPublicKeyParameters class]];
}

- (id<LibOrgBouncycastleCryptoDSA>)createDSAImplWithShort:(jshort)hashAlgorithm {
  return new_LibOrgBouncycastleCryptoSignersDSASigner_initWithLibOrgBouncycastleCryptoSignersDSAKCalculator_(new_LibOrgBouncycastleCryptoSignersHMacDSAKCalculator_initWithLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoTlsTlsUtils_createHashWithShort_(hashAlgorithm)));
}

- (jshort)getSignatureAlgorithm {
  return LibOrgBouncycastleCryptoTlsSignatureAlgorithm_dsa;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoDSA;", 0x4, 2, 3, -1, -1, -1, -1 },
    { NULL, "S", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(isValidPublicKeyWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:);
  methods[2].selector = @selector(createDSAImplWithShort:);
  methods[3].selector = @selector(getSignatureAlgorithm);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "isValidPublicKey", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", "createDSAImpl", "S" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsTlsDSSSigner = { "TlsDSSSigner", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, NULL, 7, 0x1, 4, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsTlsDSSSigner;
}

@end

void LibOrgBouncycastleCryptoTlsTlsDSSSigner_init(LibOrgBouncycastleCryptoTlsTlsDSSSigner *self) {
  LibOrgBouncycastleCryptoTlsTlsDSASigner_init(self);
}

LibOrgBouncycastleCryptoTlsTlsDSSSigner *new_LibOrgBouncycastleCryptoTlsTlsDSSSigner_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsTlsDSSSigner, init)
}

LibOrgBouncycastleCryptoTlsTlsDSSSigner *create_LibOrgBouncycastleCryptoTlsTlsDSSSigner_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsTlsDSSSigner, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsTlsDSSSigner)
