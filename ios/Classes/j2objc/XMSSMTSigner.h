//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/XMSSMTSigner.java
//

#ifndef XMSSMTSigner_H
#define XMSSMTSigner_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "StateAwareMessageSigner.h"

@class IOSByteArray;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastlePqcCryptoXmssXMSSMTSigner : NSObject < LibOrgBouncycastlePqcCryptoStateAwareMessageSigner >

#pragma mark Public

- (instancetype __nonnull)init;

- (IOSByteArray *)generateSignatureWithByteArray:(IOSByteArray *)message;

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getUpdatedPrivateKey;

- (jlong)getUsagesRemaining;

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                           withByteArray:(IOSByteArray *)signature;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoXmssXMSSMTSigner)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoXmssXMSSMTSigner_init(LibOrgBouncycastlePqcCryptoXmssXMSSMTSigner *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSMTSigner *new_LibOrgBouncycastlePqcCryptoXmssXMSSMTSigner_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSMTSigner *create_LibOrgBouncycastlePqcCryptoXmssXMSSMTSigner_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoXmssXMSSMTSigner)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // XMSSMTSigner_H
