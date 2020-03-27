//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/digest/SHA512.java
//

#ifndef SHA512_H
#define SHA512_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BCMessageDigest.h"
#include "BaseKeyGenerator.h"
#include "BaseMac.h"
#include "DigestAlgorithmProvider.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoCipherKeyGenerator;
@protocol LibOrgBouncycastleCryptoDigest;
@protocol LibOrgBouncycastleCryptoMac;
@protocol LibOrgBouncycastleJcajceProviderConfigConfigurableProvider;

@interface LibOrgBouncycastleJcajceProviderDigestSHA512 : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA512)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA512)

@interface LibOrgBouncycastleJcajceProviderDigestSHA512_Digest : LibOrgBouncycastleJcajceProviderDigestBCMessageDigest < NSCopying >

#pragma mark Public

- (instancetype __nonnull)init;

- (id)java_clone;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA512_Digest)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA512_Digest_init(LibOrgBouncycastleJcajceProviderDigestSHA512_Digest *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_Digest *new_LibOrgBouncycastleJcajceProviderDigestSHA512_Digest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_Digest *create_LibOrgBouncycastleJcajceProviderDigestSHA512_Digest_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA512_Digest)

@interface LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT : LibOrgBouncycastleJcajceProviderDigestBCMessageDigest < NSCopying >

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)bitLength;

- (id)java_clone;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT_initWithInt_(LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT *self, jint bitLength);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT *new_LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT_initWithInt_(jint bitLength) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT *create_LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT_initWithInt_(jint bitLength);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT)

@interface LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT224 : LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT224)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT224_init(LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT224 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT224 *new_LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT224_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT224 *create_LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT224_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT224)

@interface LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT256 : LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT256)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT256_init(LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT256 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT256 *new_LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT256 *create_LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA512_DigestT256)

@interface LibOrgBouncycastleJcajceProviderDigestSHA512_HashMac : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA512_HashMac)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA512_HashMac_init(LibOrgBouncycastleJcajceProviderDigestSHA512_HashMac *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_HashMac *new_LibOrgBouncycastleJcajceProviderDigestSHA512_HashMac_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_HashMac *create_LibOrgBouncycastleJcajceProviderDigestSHA512_HashMac_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA512_HashMac)

@interface LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT224 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT224)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT224_init(LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT224 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT224 *new_LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT224_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT224 *create_LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT224_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT224)

@interface LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT256 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT256)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT256_init(LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT256 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT256 *new_LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT256 *create_LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA512_HashMacT256)

@interface LibOrgBouncycastleJcajceProviderDigestSHA512_OldSHA512 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA512_OldSHA512)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA512_OldSHA512_init(LibOrgBouncycastleJcajceProviderDigestSHA512_OldSHA512 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_OldSHA512 *new_LibOrgBouncycastleJcajceProviderDigestSHA512_OldSHA512_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_OldSHA512 *create_LibOrgBouncycastleJcajceProviderDigestSHA512_OldSHA512_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA512_OldSHA512)

@interface LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGenerator : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGenerator_init(LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGenerator *new_LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGenerator *create_LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGenerator)

@interface LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT224 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT224)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT224_init(LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT224 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT224 *new_LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT224_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT224 *create_LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT224_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT224)

@interface LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT256 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT256)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT256_init(LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT256 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT256 *new_LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT256 *create_LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA512_KeyGeneratorT256)

@interface LibOrgBouncycastleJcajceProviderDigestSHA512_Mappings : LibOrgBouncycastleJcajceProviderDigestDigestAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA512_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA512_Mappings_init(LibOrgBouncycastleJcajceProviderDigestSHA512_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_Mappings *new_LibOrgBouncycastleJcajceProviderDigestSHA512_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA512_Mappings *create_LibOrgBouncycastleJcajceProviderDigestSHA512_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA512_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SHA512_H
