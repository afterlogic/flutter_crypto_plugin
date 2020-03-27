//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/digest/SHA224.java
//

#ifndef SHA224_H
#define SHA224_H

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

@interface LibOrgBouncycastleJcajceProviderDigestSHA224 : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA224)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA224)

@interface LibOrgBouncycastleJcajceProviderDigestSHA224_Digest : LibOrgBouncycastleJcajceProviderDigestBCMessageDigest < NSCopying >

#pragma mark Public

- (instancetype __nonnull)init;

- (id)java_clone;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA224_Digest)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA224_Digest_init(LibOrgBouncycastleJcajceProviderDigestSHA224_Digest *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA224_Digest *new_LibOrgBouncycastleJcajceProviderDigestSHA224_Digest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA224_Digest *create_LibOrgBouncycastleJcajceProviderDigestSHA224_Digest_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA224_Digest)

@interface LibOrgBouncycastleJcajceProviderDigestSHA224_HashMac : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA224_HashMac)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA224_HashMac_init(LibOrgBouncycastleJcajceProviderDigestSHA224_HashMac *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA224_HashMac *new_LibOrgBouncycastleJcajceProviderDigestSHA224_HashMac_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA224_HashMac *create_LibOrgBouncycastleJcajceProviderDigestSHA224_HashMac_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA224_HashMac)

@interface LibOrgBouncycastleJcajceProviderDigestSHA224_KeyGenerator : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA224_KeyGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA224_KeyGenerator_init(LibOrgBouncycastleJcajceProviderDigestSHA224_KeyGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA224_KeyGenerator *new_LibOrgBouncycastleJcajceProviderDigestSHA224_KeyGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA224_KeyGenerator *create_LibOrgBouncycastleJcajceProviderDigestSHA224_KeyGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA224_KeyGenerator)

@interface LibOrgBouncycastleJcajceProviderDigestSHA224_Mappings : LibOrgBouncycastleJcajceProviderDigestDigestAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA224_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA224_Mappings_init(LibOrgBouncycastleJcajceProviderDigestSHA224_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA224_Mappings *new_LibOrgBouncycastleJcajceProviderDigestSHA224_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA224_Mappings *create_LibOrgBouncycastleJcajceProviderDigestSHA224_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA224_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SHA224_H
