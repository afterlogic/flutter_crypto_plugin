//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/srp/SRP6Util.java
//

#ifndef SRP6Util_H
#define SRP6Util_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class JavaSecuritySecureRandom;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoAgreementSrpSRP6Util : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (JavaMathBigInteger *)calculateKWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                              withJavaMathBigInteger:(JavaMathBigInteger *)N
                                              withJavaMathBigInteger:(JavaMathBigInteger *)g;

+ (JavaMathBigInteger *)calculateKeyWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                                withJavaMathBigInteger:(JavaMathBigInteger *)N
                                                withJavaMathBigInteger:(JavaMathBigInteger *)S;

+ (JavaMathBigInteger *)calculateM1WithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                               withJavaMathBigInteger:(JavaMathBigInteger *)N
                                               withJavaMathBigInteger:(JavaMathBigInteger *)A
                                               withJavaMathBigInteger:(JavaMathBigInteger *)B
                                               withJavaMathBigInteger:(JavaMathBigInteger *)S;

+ (JavaMathBigInteger *)calculateM2WithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                               withJavaMathBigInteger:(JavaMathBigInteger *)N
                                               withJavaMathBigInteger:(JavaMathBigInteger *)A
                                               withJavaMathBigInteger:(JavaMathBigInteger *)M1
                                               withJavaMathBigInteger:(JavaMathBigInteger *)S;

+ (JavaMathBigInteger *)calculateUWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                              withJavaMathBigInteger:(JavaMathBigInteger *)N
                                              withJavaMathBigInteger:(JavaMathBigInteger *)A
                                              withJavaMathBigInteger:(JavaMathBigInteger *)B;

+ (JavaMathBigInteger *)calculateXWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                              withJavaMathBigInteger:(JavaMathBigInteger *)N
                                                       withByteArray:(IOSByteArray *)salt
                                                       withByteArray:(IOSByteArray *)identity
                                                       withByteArray:(IOSByteArray *)password;

+ (JavaMathBigInteger *)generatePrivateValueWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                                        withJavaMathBigInteger:(JavaMathBigInteger *)N
                                                        withJavaMathBigInteger:(JavaMathBigInteger *)g
                                                  withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

+ (JavaMathBigInteger *)validatePublicValueWithJavaMathBigInteger:(JavaMathBigInteger *)N
                                           withJavaMathBigInteger:(JavaMathBigInteger *)val;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoAgreementSrpSRP6Util)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementSrpSRP6Util_init(LibOrgBouncycastleCryptoAgreementSrpSRP6Util *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementSrpSRP6Util *new_LibOrgBouncycastleCryptoAgreementSrpSRP6Util_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementSrpSRP6Util *create_LibOrgBouncycastleCryptoAgreementSrpSRP6Util_init(void);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementSrpSRP6Util_calculateKWithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withJavaMathBigInteger_(id<LibOrgBouncycastleCryptoDigest> digest, JavaMathBigInteger *N, JavaMathBigInteger *g);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementSrpSRP6Util_calculateUWithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(id<LibOrgBouncycastleCryptoDigest> digest, JavaMathBigInteger *N, JavaMathBigInteger *A, JavaMathBigInteger *B);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementSrpSRP6Util_calculateXWithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withByteArray_withByteArray_withByteArray_(id<LibOrgBouncycastleCryptoDigest> digest, JavaMathBigInteger *N, IOSByteArray *salt, IOSByteArray *identity, IOSByteArray *password);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementSrpSRP6Util_generatePrivateValueWithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(id<LibOrgBouncycastleCryptoDigest> digest, JavaMathBigInteger *N, JavaMathBigInteger *g, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementSrpSRP6Util_validatePublicValueWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *N, JavaMathBigInteger *val);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementSrpSRP6Util_calculateM1WithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(id<LibOrgBouncycastleCryptoDigest> digest, JavaMathBigInteger *N, JavaMathBigInteger *A, JavaMathBigInteger *B, JavaMathBigInteger *S);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementSrpSRP6Util_calculateM2WithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(id<LibOrgBouncycastleCryptoDigest> digest, JavaMathBigInteger *N, JavaMathBigInteger *A, JavaMathBigInteger *M1, JavaMathBigInteger *S);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementSrpSRP6Util_calculateKeyWithLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_withJavaMathBigInteger_(id<LibOrgBouncycastleCryptoDigest> digest, JavaMathBigInteger *N, JavaMathBigInteger *S);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoAgreementSrpSRP6Util)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SRP6Util_H
