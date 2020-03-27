//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/qtesla/QTESLASigner.java
//

#ifndef QTESLASigner_H
#define QTESLASigner_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "MessageSigner.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastlePqcCryptoQteslaQTESLASigner : NSObject < LibOrgBouncycastlePqcCryptoMessageSigner >

#pragma mark Public

- (instancetype __nonnull)init;

- (IOSByteArray *)generateSignatureWithByteArray:(IOSByteArray *)message;

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                           withByteArray:(IOSByteArray *)signature;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoQteslaQTESLASigner)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaQTESLASigner_init(LibOrgBouncycastlePqcCryptoQteslaQTESLASigner *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoQteslaQTESLASigner *new_LibOrgBouncycastlePqcCryptoQteslaQTESLASigner_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoQteslaQTESLASigner *create_LibOrgBouncycastlePqcCryptoQteslaQTESLASigner_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoQteslaQTESLASigner)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // QTESLASigner_H
