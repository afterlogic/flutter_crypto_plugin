//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/srp/SRP6Client.java
//

#include "CryptoException.h"
#include "Digest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "SRP6Client.h"
#include "SRP6GroupParameters.h"
#include "SRP6Util.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoAgreementSrpSRP6Client ()

- (JavaMathBigInteger *)calculateS;

@end

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementSrpSRP6Client_calculateS(LibOrgBouncycastleCryptoAgreementSrpSRP6Client *self);

@implementation LibOrgBouncycastleCryptoAgreementSrpSRP6Client

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoAgreementSrpSRP6Client_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithJavaMathBigInteger:(JavaMathBigInteger *)N
              withJavaMathBigInteger:(JavaMathBigInteger *)g
  withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
        withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  self->N_ = N;
  self->g_ = g;
  self->digest_ = digest;
  self->random_ = random;
}

- (void)init__WithLibOrgBouncycastleCryptoParamsSRP6GroupParameters:(LibOrgBouncycastleCryptoParamsSRP6GroupParameters *)group
                                 withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                       withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  [self init__WithJavaMathBigInteger:[((LibOrgBouncycastleCryptoParamsSRP6GroupParameters *) nil_chk(group)) getN] withJavaMathBigInteger:[group getG] withLibOrgBouncycastleCryptoDigest:digest withJavaSecuritySecureRandom:random];
}

- (JavaMathBigInteger *)generateClientCredentialsWithByteArray:(IOSByteArray *)salt
                                                 withByteArray:(IOSByteArray *)identity
                                                 withByteArray:(IOSByteArray *)password {
  self->x_ = LibOrgBouncycastleCryptoAgreementSrpSRP6Util_calculateXWithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withByteArray_withByteArray_withByteArray_(digest_, N_, salt, identity, password);
  self->a_ = [self selectPrivateValue];
  self->A_ = [((JavaMathBigInteger *) nil_chk(g_)) modPowWithJavaMathBigInteger:a_ withJavaMathBigInteger:N_];
  return A_;
}

- (JavaMathBigInteger *)calculateSecretWithJavaMathBigInteger:(JavaMathBigInteger *)serverB {
  self->B_ = LibOrgBouncycastleCryptoAgreementSrpSRP6Util_validatePublicValueWithJavaMathBigInteger_withJavaMathBigInteger_(N_, serverB);
  self->u_ = LibOrgBouncycastleCryptoAgreementSrpSRP6Util_calculateUWithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(digest_, N_, A_, B_);
  self->S_ = LibOrgBouncycastleCryptoAgreementSrpSRP6Client_calculateS(self);
  return S_;
}

- (JavaMathBigInteger *)selectPrivateValue {
  return LibOrgBouncycastleCryptoAgreementSrpSRP6Util_generatePrivateValueWithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(digest_, N_, g_, random_);
}

- (JavaMathBigInteger *)calculateS {
  return LibOrgBouncycastleCryptoAgreementSrpSRP6Client_calculateS(self);
}

- (JavaMathBigInteger *)calculateClientEvidenceMessage {
  if (self->A_ == nil || self->B_ == nil || self->S_ == nil) {
    @throw new_LibOrgBouncycastleCryptoCryptoException_initWithNSString_(@"Impossible to compute M1: some data are missing from the previous operations (A,B,S)");
  }
  self->M1_ = LibOrgBouncycastleCryptoAgreementSrpSRP6Util_calculateM1WithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(digest_, N_, A_, B_, S_);
  return M1_;
}

- (jboolean)verifyServerEvidenceMessageWithJavaMathBigInteger:(JavaMathBigInteger *)serverM2 {
  if (self->A_ == nil || self->M1_ == nil || self->S_ == nil) {
    @throw new_LibOrgBouncycastleCryptoCryptoException_initWithNSString_(@"Impossible to compute and verify M2: some data are missing from the previous operations (A,M1,S)");
  }
  JavaMathBigInteger *computedM2 = LibOrgBouncycastleCryptoAgreementSrpSRP6Util_calculateM2WithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(digest_, N_, A_, M1_, S_);
  if ([((JavaMathBigInteger *) nil_chk(computedM2)) isEqual:serverM2]) {
    self->M2_ = serverM2;
    return true;
  }
  return false;
}

- (JavaMathBigInteger *)calculateSessionKey {
  if (self->S_ == nil || self->M1_ == nil || self->M2_ == nil) {
    @throw new_LibOrgBouncycastleCryptoCryptoException_initWithNSString_(@"Impossible to compute Key: some data are missing from the previous operations (S,M1,M2)");
  }
  self->Key_ = LibOrgBouncycastleCryptoAgreementSrpSRP6Util_calculateKeyWithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withJavaMathBigInteger_(digest_, N_, S_);
  return Key_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 2, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, 5, 6, 7, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, 7, -1, -1, -1 },
    { NULL, "Z", 0x1, 8, 6, 7, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, 7, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithJavaMathBigInteger:withJavaMathBigInteger:withLibOrgBouncycastleCryptoDigest:withJavaSecuritySecureRandom:);
  methods[2].selector = @selector(init__WithLibOrgBouncycastleCryptoParamsSRP6GroupParameters:withLibOrgBouncycastleCryptoDigest:withJavaSecuritySecureRandom:);
  methods[3].selector = @selector(generateClientCredentialsWithByteArray:withByteArray:withByteArray:);
  methods[4].selector = @selector(calculateSecretWithJavaMathBigInteger:);
  methods[5].selector = @selector(selectPrivateValue);
  methods[6].selector = @selector(calculateS);
  methods[7].selector = @selector(calculateClientEvidenceMessage);
  methods[8].selector = @selector(verifyServerEvidenceMessageWithJavaMathBigInteger:);
  methods[9].selector = @selector(calculateSessionKey);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "N_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "g_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "a_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "A_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "B_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "x_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "u_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "S_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "M1_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "M2_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "Key_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "digest_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LJavaMathBigInteger;LJavaMathBigInteger;LLibOrgBouncycastleCryptoDigest;LJavaSecuritySecureRandom;", "LLibOrgBouncycastleCryptoParamsSRP6GroupParameters;LLibOrgBouncycastleCryptoDigest;LJavaSecuritySecureRandom;", "generateClientCredentials", "[B[B[B", "calculateSecret", "LJavaMathBigInteger;", "LLibOrgBouncycastleCryptoCryptoException;", "verifyServerEvidenceMessage" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoAgreementSrpSRP6Client = { "SRP6Client", "lib.org.bouncycastle.crypto.agreement.srp", ptrTable, methods, fields, 7, 0x1, 10, 13, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoAgreementSrpSRP6Client;
}

@end

void LibOrgBouncycastleCryptoAgreementSrpSRP6Client_init(LibOrgBouncycastleCryptoAgreementSrpSRP6Client *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoAgreementSrpSRP6Client *new_LibOrgBouncycastleCryptoAgreementSrpSRP6Client_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoAgreementSrpSRP6Client, init)
}

LibOrgBouncycastleCryptoAgreementSrpSRP6Client *create_LibOrgBouncycastleCryptoAgreementSrpSRP6Client_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoAgreementSrpSRP6Client, init)
}

JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementSrpSRP6Client_calculateS(LibOrgBouncycastleCryptoAgreementSrpSRP6Client *self) {
  JavaMathBigInteger *k = LibOrgBouncycastleCryptoAgreementSrpSRP6Util_calculateKWithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withJavaMathBigInteger_(self->digest_, self->N_, self->g_);
  JavaMathBigInteger *exp = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(self->u_)) multiplyWithJavaMathBigInteger:self->x_])) addWithJavaMathBigInteger:self->a_];
  JavaMathBigInteger *tmp = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(self->g_)) modPowWithJavaMathBigInteger:self->x_ withJavaMathBigInteger:self->N_])) multiplyWithJavaMathBigInteger:k])) modWithJavaMathBigInteger:self->N_];
  return [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(self->B_)) subtractWithJavaMathBigInteger:tmp])) modWithJavaMathBigInteger:self->N_])) modPowWithJavaMathBigInteger:exp withJavaMathBigInteger:self->N_];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoAgreementSrpSRP6Client)
