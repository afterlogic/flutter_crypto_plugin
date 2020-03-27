//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/SignerWithRecovery.java
//

#ifndef SignerWithRecovery_H
#define SignerWithRecovery_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Signer.h"

@class IOSByteArray;

@protocol LibOrgBouncycastleCryptoSignerWithRecovery < LibOrgBouncycastleCryptoSigner, JavaObject >

- (jboolean)hasFullMessage;

- (IOSByteArray *)getRecoveredMessage;

- (void)updateWithRecoveredMessageWithByteArray:(IOSByteArray *)signature;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoSignerWithRecovery)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignerWithRecovery)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SignerWithRecovery_H
