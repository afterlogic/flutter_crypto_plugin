//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/Committer.java
//

#ifndef Committer_H
#define Committer_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleCryptoCommitment;

@protocol LibOrgBouncycastleCryptoCommitter < JavaObject >

- (LibOrgBouncycastleCryptoCommitment *)commitWithByteArray:(IOSByteArray *)message;

- (jboolean)isRevealedWithLibOrgBouncycastleCryptoCommitment:(LibOrgBouncycastleCryptoCommitment *)commitment
                                               withByteArray:(IOSByteArray *)message;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoCommitter)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoCommitter)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Committer_H
