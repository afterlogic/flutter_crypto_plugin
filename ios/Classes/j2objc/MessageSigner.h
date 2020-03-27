//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/MessageSigner.java
//

#ifndef MessageSigner_H
#define MessageSigner_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@protocol LibOrgBouncycastlePqcCryptoMessageSigner < JavaObject >

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (IOSByteArray *)generateSignatureWithByteArray:(IOSByteArray *)message;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                           withByteArray:(IOSByteArray *)signature;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoMessageSigner)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoMessageSigner)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // MessageSigner_H
