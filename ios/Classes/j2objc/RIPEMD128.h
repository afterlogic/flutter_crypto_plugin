//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/digest/RIPEMD128.java
//

#ifndef RIPEMD128_H
#define RIPEMD128_H

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

@interface LibOrgBouncycastleJcajceProviderDigestRIPEMD128 : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestRIPEMD128)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestRIPEMD128)

@interface LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Digest : LibOrgBouncycastleJcajceProviderDigestBCMessageDigest < NSCopying >

#pragma mark Public

- (instancetype __nonnull)init;

- (id)java_clone;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Digest)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Digest_init(LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Digest *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Digest *new_LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Digest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Digest *create_LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Digest_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Digest)

@interface LibOrgBouncycastleJcajceProviderDigestRIPEMD128_HashMac : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestRIPEMD128_HashMac)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestRIPEMD128_HashMac_init(LibOrgBouncycastleJcajceProviderDigestRIPEMD128_HashMac *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestRIPEMD128_HashMac *new_LibOrgBouncycastleJcajceProviderDigestRIPEMD128_HashMac_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestRIPEMD128_HashMac *create_LibOrgBouncycastleJcajceProviderDigestRIPEMD128_HashMac_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestRIPEMD128_HashMac)

@interface LibOrgBouncycastleJcajceProviderDigestRIPEMD128_KeyGenerator : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestRIPEMD128_KeyGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestRIPEMD128_KeyGenerator_init(LibOrgBouncycastleJcajceProviderDigestRIPEMD128_KeyGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestRIPEMD128_KeyGenerator *new_LibOrgBouncycastleJcajceProviderDigestRIPEMD128_KeyGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestRIPEMD128_KeyGenerator *create_LibOrgBouncycastleJcajceProviderDigestRIPEMD128_KeyGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestRIPEMD128_KeyGenerator)

@interface LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Mappings : LibOrgBouncycastleJcajceProviderDigestDigestAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Mappings_init(LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Mappings *new_LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Mappings *create_LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestRIPEMD128_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RIPEMD128_H
