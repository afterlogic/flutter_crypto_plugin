//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/DHAgreement.java
//

#ifndef DHAgreement_H
#define DHAgreement_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleCryptoParamsDHPublicKeyParameters;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoAgreementDHAgreement : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (JavaMathBigInteger *)calculateAgreementWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)pub
                                                                           withJavaMathBigInteger:(JavaMathBigInteger *)message;

- (JavaMathBigInteger *)calculateMessage;

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoAgreementDHAgreement)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementDHAgreement_init(LibOrgBouncycastleCryptoAgreementDHAgreement *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementDHAgreement *new_LibOrgBouncycastleCryptoAgreementDHAgreement_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementDHAgreement *create_LibOrgBouncycastleCryptoAgreementDHAgreement_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoAgreementDHAgreement)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DHAgreement_H