//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/digest/Whirlpool.java
//

#ifndef Whirlpool_H
#define Whirlpool_H

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

@interface LibOrgBouncycastleJcajceProviderDigestWhirlpool : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestWhirlpool)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestWhirlpool)

@interface LibOrgBouncycastleJcajceProviderDigestWhirlpool_Digest : LibOrgBouncycastleJcajceProviderDigestBCMessageDigest < NSCopying >

#pragma mark Public

- (instancetype __nonnull)init;

- (id)java_clone;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestWhirlpool_Digest)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestWhirlpool_Digest_init(LibOrgBouncycastleJcajceProviderDigestWhirlpool_Digest *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestWhirlpool_Digest *new_LibOrgBouncycastleJcajceProviderDigestWhirlpool_Digest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestWhirlpool_Digest *create_LibOrgBouncycastleJcajceProviderDigestWhirlpool_Digest_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestWhirlpool_Digest)

@interface LibOrgBouncycastleJcajceProviderDigestWhirlpool_HashMac : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestWhirlpool_HashMac)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestWhirlpool_HashMac_init(LibOrgBouncycastleJcajceProviderDigestWhirlpool_HashMac *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestWhirlpool_HashMac *new_LibOrgBouncycastleJcajceProviderDigestWhirlpool_HashMac_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestWhirlpool_HashMac *create_LibOrgBouncycastleJcajceProviderDigestWhirlpool_HashMac_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestWhirlpool_HashMac)

@interface LibOrgBouncycastleJcajceProviderDigestWhirlpool_KeyGenerator : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestWhirlpool_KeyGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestWhirlpool_KeyGenerator_init(LibOrgBouncycastleJcajceProviderDigestWhirlpool_KeyGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestWhirlpool_KeyGenerator *new_LibOrgBouncycastleJcajceProviderDigestWhirlpool_KeyGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestWhirlpool_KeyGenerator *create_LibOrgBouncycastleJcajceProviderDigestWhirlpool_KeyGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestWhirlpool_KeyGenerator)

@interface LibOrgBouncycastleJcajceProviderDigestWhirlpool_Mappings : LibOrgBouncycastleJcajceProviderDigestDigestAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestWhirlpool_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestWhirlpool_Mappings_init(LibOrgBouncycastleJcajceProviderDigestWhirlpool_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestWhirlpool_Mappings *new_LibOrgBouncycastleJcajceProviderDigestWhirlpool_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestWhirlpool_Mappings *create_LibOrgBouncycastleJcajceProviderDigestWhirlpool_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestWhirlpool_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Whirlpool_H