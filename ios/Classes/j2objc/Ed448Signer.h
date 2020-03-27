//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/Ed448Signer.java
//

#ifndef Ed448Signer_H
#define Ed448Signer_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Signer.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoSignersEd448Signer : NSObject < LibOrgBouncycastleCryptoSigner >

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)context;

- (IOSByteArray *)generateSignature;

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters OBJC_METHOD_FAMILY_NONE;

- (void)reset;

- (void)updateWithByte:(jbyte)b;

- (void)updateWithByteArray:(IOSByteArray *)buf
                    withInt:(jint)off
                    withInt:(jint)len;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)signature;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoSignersEd448Signer)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersEd448Signer_initWithByteArray_(LibOrgBouncycastleCryptoSignersEd448Signer *self, IOSByteArray *context);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersEd448Signer *new_LibOrgBouncycastleCryptoSignersEd448Signer_initWithByteArray_(IOSByteArray *context) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersEd448Signer *create_LibOrgBouncycastleCryptoSignersEd448Signer_initWithByteArray_(IOSByteArray *context);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersEd448Signer)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Ed448Signer_H