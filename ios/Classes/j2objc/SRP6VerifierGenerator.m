//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/srp/SRP6VerifierGenerator.java
//

#include "Digest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "SRP6GroupParameters.h"
#include "SRP6Util.h"
#include "SRP6VerifierGenerator.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleCryptoAgreementSrpSRP6VerifierGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoAgreementSrpSRP6VerifierGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithJavaMathBigInteger:(JavaMathBigInteger *)N
              withJavaMathBigInteger:(JavaMathBigInteger *)g
  withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest {
  self->N_ = N;
  self->g_ = g;
  self->digest_ = digest;
}

- (void)init__WithLibOrgBouncycastleCryptoParamsSRP6GroupParameters:(LibOrgBouncycastleCryptoParamsSRP6GroupParameters *)group
                                 withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest {
  self->N_ = [((LibOrgBouncycastleCryptoParamsSRP6GroupParameters *) nil_chk(group)) getN];
  self->g_ = [group getG];
  self->digest_ = digest;
}

- (JavaMathBigInteger *)generateVerifierWithByteArray:(IOSByteArray *)salt
                                        withByteArray:(IOSByteArray *)identity
                                        withByteArray:(IOSByteArray *)password {
  JavaMathBigInteger *x = LibOrgBouncycastleCryptoAgreementSrpSRP6Util_calculateXWithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withByteArray_withByteArray_withByteArray_(digest_, N_, salt, identity, password);
  return [((JavaMathBigInteger *) nil_chk(g_)) modPowWithJavaMathBigInteger:x withJavaMathBigInteger:N_];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 2, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, 3, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithJavaMathBigInteger:withJavaMathBigInteger:withLibOrgBouncycastleCryptoDigest:);
  methods[2].selector = @selector(init__WithLibOrgBouncycastleCryptoParamsSRP6GroupParameters:withLibOrgBouncycastleCryptoDigest:);
  methods[3].selector = @selector(generateVerifierWithByteArray:withByteArray:withByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "N_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "g_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "digest_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LJavaMathBigInteger;LJavaMathBigInteger;LLibOrgBouncycastleCryptoDigest;", "LLibOrgBouncycastleCryptoParamsSRP6GroupParameters;LLibOrgBouncycastleCryptoDigest;", "generateVerifier", "[B[B[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoAgreementSrpSRP6VerifierGenerator = { "SRP6VerifierGenerator", "lib.org.bouncycastle.crypto.agreement.srp", ptrTable, methods, fields, 7, 0x1, 4, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoAgreementSrpSRP6VerifierGenerator;
}

@end

void LibOrgBouncycastleCryptoAgreementSrpSRP6VerifierGenerator_init(LibOrgBouncycastleCryptoAgreementSrpSRP6VerifierGenerator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoAgreementSrpSRP6VerifierGenerator *new_LibOrgBouncycastleCryptoAgreementSrpSRP6VerifierGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoAgreementSrpSRP6VerifierGenerator, init)
}

LibOrgBouncycastleCryptoAgreementSrpSRP6VerifierGenerator *create_LibOrgBouncycastleCryptoAgreementSrpSRP6VerifierGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoAgreementSrpSRP6VerifierGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoAgreementSrpSRP6VerifierGenerator)
