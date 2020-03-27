//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/DSA.java
//

#ifndef DSA_H
#define DSA_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSObjectArray;
@class JavaMathBigInteger;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@protocol LibOrgBouncycastleCryptoDSA < JavaObject >

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (IOSObjectArray *)generateSignatureWithByteArray:(IOSByteArray *)message;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                  withJavaMathBigInteger:(JavaMathBigInteger *)r
                  withJavaMathBigInteger:(JavaMathBigInteger *)s;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoDSA)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoDSA)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DSA_H
