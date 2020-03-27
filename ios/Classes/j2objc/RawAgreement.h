//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/RawAgreement.java
//

#ifndef RawAgreement_H
#define RawAgreement_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@protocol LibOrgBouncycastleCryptoRawAgreement < JavaObject >

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters OBJC_METHOD_FAMILY_NONE;

- (jint)getAgreementSize;

- (void)calculateAgreementWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)publicKey
                                                         withByteArray:(IOSByteArray *)buf
                                                               withInt:(jint)off;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoRawAgreement)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoRawAgreement)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RawAgreement_H
