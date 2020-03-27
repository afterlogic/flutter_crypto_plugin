//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/sphincs/PqcJcajceSphincsSignatureSpi.java
//

#ifndef PqcJcajceSphincsSignatureSpi_H
#define PqcJcajceSphincsSignatureSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/SignatureSpi.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;
@protocol JavaSecuritySpecAlgorithmParameterSpec;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi : JavaSecuritySignatureSpi

#pragma mark Protected

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                  withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)treeDigest
          withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer:(LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *)signer;

- (id)engineGetParameterWithNSString:(NSString *)param;

- (void)engineInitSignWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privateKey;

- (void)engineInitSignWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privateKey
                    withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)engineInitVerifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)publicKey;

- (void)engineSetParameterWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params;

- (void)engineSetParameterWithNSString:(NSString *)param
                                withId:(id)value;

- (IOSByteArray *)engineSign;

- (void)engineUpdateWithByte:(jbyte)b;

- (void)engineUpdateWithByteArray:(IOSByteArray *)b
                          withInt:(jint)off
                          withInt:(jint)len;

- (jboolean)engineVerifyWithByteArray:(IOSByteArray *)sigBytes;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer_(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi *self, id<LibOrgBouncycastleCryptoDigest> digest, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *signer);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi *new_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer_(id<LibOrgBouncycastleCryptoDigest> digest, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *signer) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi *create_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer_(id<LibOrgBouncycastleCryptoDigest> digest, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *signer);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi)

@interface LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512 : LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)arg0
                  withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)arg1
          withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer:(LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512_init(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512 *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512 *new_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512 *create_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512)

@interface LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512 : LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)arg0
                  withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)arg1
          withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer:(LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512_init(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512 *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512 *new_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512 *create_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PqcJcajceSphincsSignatureSpi_H
