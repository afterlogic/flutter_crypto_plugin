//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/GenericSigner.java
//

#ifndef GenericSigner_H
#define GenericSigner_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Signer.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoAsymmetricBlockCipher;
@protocol LibOrgBouncycastleCryptoCipherParameters;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoSignersGenericSigner : NSObject < LibOrgBouncycastleCryptoSigner >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)engine
                                             withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

- (IOSByteArray *)generateSignature;

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters OBJC_METHOD_FAMILY_NONE;

- (void)reset;

- (void)updateWithByte:(jbyte)input;

- (void)updateWithByteArray:(IOSByteArray *)input
                    withInt:(jint)inOff
                    withInt:(jint)length;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)signature;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoSignersGenericSigner)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersGenericSigner_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoSignersGenericSigner *self, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> engine, id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersGenericSigner *new_LibOrgBouncycastleCryptoSignersGenericSigner_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> engine, id<LibOrgBouncycastleCryptoDigest> digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersGenericSigner *create_LibOrgBouncycastleCryptoSignersGenericSigner_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> engine, id<LibOrgBouncycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersGenericSigner)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GenericSigner_H
