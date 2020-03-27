//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/RSADigestSigner.java
//

#ifndef RSADigestSigner_H
#define RSADigestSigner_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Signer.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@protocol LibOrgBouncycastleCryptoCipherParameters;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoSignersRSADigestSigner : NSObject < LibOrgBouncycastleCryptoSigner >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                  withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)digestOid;

- (IOSByteArray *)generateSignature;

- (NSString *)getAlgorithmName;

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

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoSignersRSADigestSigner)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersRSADigestSigner_initWithLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoSignersRSADigestSigner *self, id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersRSADigestSigner *new_LibOrgBouncycastleCryptoSignersRSADigestSigner_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersRSADigestSigner *create_LibOrgBouncycastleCryptoSignersRSADigestSigner_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersRSADigestSigner_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleCryptoSignersRSADigestSigner *self, id<LibOrgBouncycastleCryptoDigest> digest, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestOid);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersRSADigestSigner *new_LibOrgBouncycastleCryptoSignersRSADigestSigner_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(id<LibOrgBouncycastleCryptoDigest> digest, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestOid) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersRSADigestSigner *create_LibOrgBouncycastleCryptoSignersRSADigestSigner_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(id<LibOrgBouncycastleCryptoDigest> digest, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestOid);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersRSADigestSigner)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RSADigestSigner_H
