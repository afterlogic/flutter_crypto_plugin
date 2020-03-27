//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/prng/SP800SecureRandom.java
//

#ifndef SP800SecureRandom_H
#define SP800SecureRandom_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/SecureRandom.h"

@class IOSByteArray;
@class JavaSecurityProvider;
@class JavaSecuritySecureRandomSpi;
@protocol LibOrgBouncycastleCryptoPrngDRBGProvider;
@protocol LibOrgBouncycastleCryptoPrngEntropySource;

@interface LibOrgBouncycastleCryptoPrngSP800SecureRandom : JavaSecuritySecureRandom

#pragma mark Public

- (IOSByteArray *)generateSeedWithInt:(jint)numBytes;

- (void)nextBytesWithByteArray:(IOSByteArray *)bytes;

- (void)reseedWithByteArray:(IOSByteArray *)additionalInput;

- (void)setSeedWithByteArray:(IOSByteArray *)seed;

- (void)setSeedWithLong:(jlong)seed;

#pragma mark Package-Private

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)randomSource
             withLibOrgBouncycastleCryptoPrngEntropySource:(id<LibOrgBouncycastleCryptoPrngEntropySource>)entropySource
              withLibOrgBouncycastleCryptoPrngDRBGProvider:(id<LibOrgBouncycastleCryptoPrngDRBGProvider>)drbgProvider
                                               withBoolean:(jboolean)predictionResistant;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaSecuritySecureRandomSpi:(JavaSecuritySecureRandomSpi *)arg0
                                     withJavaSecurityProvider:(JavaSecurityProvider *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoPrngSP800SecureRandom)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoPrngSP800SecureRandom_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoPrngEntropySource_withLibOrgBouncycastleCryptoPrngDRBGProvider_withBoolean_(LibOrgBouncycastleCryptoPrngSP800SecureRandom *self, JavaSecuritySecureRandom *randomSource, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource, id<LibOrgBouncycastleCryptoPrngDRBGProvider> drbgProvider, jboolean predictionResistant);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngSP800SecureRandom *new_LibOrgBouncycastleCryptoPrngSP800SecureRandom_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoPrngEntropySource_withLibOrgBouncycastleCryptoPrngDRBGProvider_withBoolean_(JavaSecuritySecureRandom *randomSource, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource, id<LibOrgBouncycastleCryptoPrngDRBGProvider> drbgProvider, jboolean predictionResistant) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngSP800SecureRandom *create_LibOrgBouncycastleCryptoPrngSP800SecureRandom_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoPrngEntropySource_withLibOrgBouncycastleCryptoPrngDRBGProvider_withBoolean_(JavaSecuritySecureRandom *randomSource, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource, id<LibOrgBouncycastleCryptoPrngDRBGProvider> drbgProvider, jboolean predictionResistant);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoPrngSP800SecureRandom)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SP800SecureRandom_H
