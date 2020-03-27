//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/TLSKDF.java
//

#ifndef TLSKDF_H
#define TLSKDF_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AlgorithmProvider.h"
#include "BaseSecretKeyFactory.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@protocol JavaSecuritySpecKeySpec;
@protocol JavaxCryptoSecretKey;
@protocol LibOrgBouncycastleCryptoMac;
@protocol LibOrgBouncycastleJcajceProviderConfigConfigurableProvider;

@interface LibOrgBouncycastleJcajceProviderSymmetricTLSKDF : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_init(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF *new_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF *create_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF)

@interface LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLSKeyMaterialFactory : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseSecretKeyFactory

#pragma mark Protected

- (instancetype __nonnull)initWithNSString:(NSString *)algName;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLSKeyMaterialFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLSKeyMaterialFactory_initWithNSString_(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLSKeyMaterialFactory *self, NSString *algName);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLSKeyMaterialFactory *new_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLSKeyMaterialFactory_initWithNSString_(NSString *algName) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLSKeyMaterialFactory *create_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLSKeyMaterialFactory_initWithNSString_(NSString *algName);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLSKeyMaterialFactory)

@interface LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS10 : LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLSKeyMaterialFactory

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (id<JavaxCryptoSecretKey>)engineGenerateSecretWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS10)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS10_init(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS10 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS10 *new_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS10_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS10 *create_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS10_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS10)

@interface LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS11 : LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLSKeyMaterialFactory

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (id<JavaxCryptoSecretKey>)engineGenerateSecretWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS11)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS11_init(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS11 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS11 *new_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS11_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS11 *create_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS11_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS11)

@interface LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12 : LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLSKeyMaterialFactory

#pragma mark Protected

- (instancetype __nonnull)initWithNSString:(NSString *)algName
           withLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)prf;

- (id<JavaxCryptoSecretKey>)engineGenerateSecretWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12_initWithNSString_withLibOrgBouncycastleCryptoMac_(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12 *self, NSString *algName, id<LibOrgBouncycastleCryptoMac> prf);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12 *new_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12_initWithNSString_withLibOrgBouncycastleCryptoMac_(NSString *algName, id<LibOrgBouncycastleCryptoMac> prf) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12 *create_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12_initWithNSString_withLibOrgBouncycastleCryptoMac_(NSString *algName, id<LibOrgBouncycastleCryptoMac> prf);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12)

@interface LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA256 : LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
           withLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA256)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA256_init(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA256 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA256 *new_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA256 *create_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA256)

@interface LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA384 : LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
           withLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA384)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA384_init(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA384 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA384 *new_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA384_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA384 *create_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA384_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA384)

@interface LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA512 : LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
           withLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA512)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA512_init(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA512 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA512 *new_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA512_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA512 *create_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA512_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_TLS12withSHA512)

@interface LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_Mappings : LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricTLSKDF_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TLSKDF_H
