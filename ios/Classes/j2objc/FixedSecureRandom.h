//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/prng/FixedSecureRandom.java
//

#ifndef FixedSecureRandom_H
#define FixedSecureRandom_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/SecureRandom.h"

@class IOSByteArray;
@class IOSObjectArray;
@class JavaSecurityProvider;
@class JavaSecuritySecureRandomSpi;

@interface LibOrgBouncycastleCryptoPrngFixedSecureRandom : JavaSecuritySecureRandom

#pragma mark Public

- (instancetype __nonnull)initWithBoolean:(jboolean)intPad
                            withByteArray:(IOSByteArray *)value;

- (instancetype __nonnull)initWithBoolean:(jboolean)intPad
                           withByteArray2:(IOSObjectArray *)values;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)value;

- (instancetype __nonnull)initWithByteArray2:(IOSObjectArray *)values;

- (IOSByteArray *)generateSeedWithInt:(jint)numBytes;

- (jboolean)isExhausted;

- (void)nextBytesWithByteArray:(IOSByteArray *)bytes;

- (jint)nextInt;

- (jlong)nextLong;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaSecuritySecureRandomSpi:(JavaSecuritySecureRandomSpi *)arg0
                                     withJavaSecurityProvider:(JavaSecurityProvider *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoPrngFixedSecureRandom)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoPrngFixedSecureRandom_initWithByteArray_(LibOrgBouncycastleCryptoPrngFixedSecureRandom *self, IOSByteArray *value);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngFixedSecureRandom *new_LibOrgBouncycastleCryptoPrngFixedSecureRandom_initWithByteArray_(IOSByteArray *value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngFixedSecureRandom *create_LibOrgBouncycastleCryptoPrngFixedSecureRandom_initWithByteArray_(IOSByteArray *value);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoPrngFixedSecureRandom_initWithByteArray2_(LibOrgBouncycastleCryptoPrngFixedSecureRandom *self, IOSObjectArray *values);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngFixedSecureRandom *new_LibOrgBouncycastleCryptoPrngFixedSecureRandom_initWithByteArray2_(IOSObjectArray *values) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngFixedSecureRandom *create_LibOrgBouncycastleCryptoPrngFixedSecureRandom_initWithByteArray2_(IOSObjectArray *values);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoPrngFixedSecureRandom_initWithBoolean_withByteArray_(LibOrgBouncycastleCryptoPrngFixedSecureRandom *self, jboolean intPad, IOSByteArray *value);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngFixedSecureRandom *new_LibOrgBouncycastleCryptoPrngFixedSecureRandom_initWithBoolean_withByteArray_(jboolean intPad, IOSByteArray *value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngFixedSecureRandom *create_LibOrgBouncycastleCryptoPrngFixedSecureRandom_initWithBoolean_withByteArray_(jboolean intPad, IOSByteArray *value);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoPrngFixedSecureRandom_initWithBoolean_withByteArray2_(LibOrgBouncycastleCryptoPrngFixedSecureRandom *self, jboolean intPad, IOSObjectArray *values);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngFixedSecureRandom *new_LibOrgBouncycastleCryptoPrngFixedSecureRandom_initWithBoolean_withByteArray2_(jboolean intPad, IOSObjectArray *values) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngFixedSecureRandom *create_LibOrgBouncycastleCryptoPrngFixedSecureRandom_initWithBoolean_withByteArray2_(jboolean intPad, IOSObjectArray *values);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoPrngFixedSecureRandom)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // FixedSecureRandom_H
