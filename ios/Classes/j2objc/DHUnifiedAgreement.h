//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/DHUnifiedAgreement.java
//

#ifndef DHUnifiedAgreement_H
#define DHUnifiedAgreement_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoAgreementDHUnifiedAgreement : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (IOSByteArray *)calculateAgreementWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)pubKey;

- (jint)getFieldSize;

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)key OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoAgreementDHUnifiedAgreement)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementDHUnifiedAgreement_init(LibOrgBouncycastleCryptoAgreementDHUnifiedAgreement *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementDHUnifiedAgreement *new_LibOrgBouncycastleCryptoAgreementDHUnifiedAgreement_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementDHUnifiedAgreement *create_LibOrgBouncycastleCryptoAgreementDHUnifiedAgreement_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoAgreementDHUnifiedAgreement)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DHUnifiedAgreement_H