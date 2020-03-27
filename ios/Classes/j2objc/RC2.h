//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/RC2.java
//

#ifndef RC2_H
#define RC2_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AlgorithmProvider.h"
#include "BaseAlgorithmParameterGenerator.h"
#include "BaseAlgorithmParameters.h"
#include "BaseBlockCipher.h"
#include "BaseKeyGenerator.h"
#include "BaseMac.h"
#include "BaseWrapCipher.h"
#include "J2ObjC_header.h"
#include "PBESecretKeyFactory.h"

@class IOSByteArray;
@class IOSClass;
@class JavaSecurityAlgorithmParameters;
@class JavaSecuritySecureRandom;
@class JavaxCryptoSpecRC2ParameterSpec;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleCryptoBufferedBlockCipher;
@class LibOrgBouncycastleCryptoCipherKeyGenerator;
@protocol JavaSecuritySpecAlgorithmParameterSpec;
@protocol LibOrgBouncycastleCryptoBlockCipher;
@protocol LibOrgBouncycastleCryptoMac;
@protocol LibOrgBouncycastleCryptoModesAEADBlockCipher;
@protocol LibOrgBouncycastleCryptoWrapper;
@protocol LibOrgBouncycastleJcajceProviderConfigConfigurableProvider;
@protocol LibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider;

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2 : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_ECB : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                          withBoolean:(jboolean)arg1
                                                              withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1
                                                              withInt:(jint)arg2
                                                              withInt:(jint)arg3
                                                              withInt:(jint)arg4 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                  withBoolean:(jboolean)arg1
                                                                      withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                      withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0
                                                                   withBoolean:(jboolean)arg1
                                                                       withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider:(id<LibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_ECB)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_ECB_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_ECB *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_ECB *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_ECB_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_ECB *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_ECB_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_ECB)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_CBC : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                          withBoolean:(jboolean)arg1
                                                              withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1
                                                              withInt:(jint)arg2
                                                              withInt:(jint)arg3
                                                              withInt:(jint)arg4 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                  withBoolean:(jboolean)arg1
                                                                      withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                      withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0
                                                                   withBoolean:(jboolean)arg1
                                                                       withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider:(id<LibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_CBC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_CBC_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_CBC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_CBC *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_CBC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_CBC *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_CBC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_CBC)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_Wrap : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoWrapper:(id<LibOrgBouncycastleCryptoWrapper>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoWrapper:(id<LibOrgBouncycastleCryptoWrapper>)arg0
                                                          withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_Wrap)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_Wrap_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_Wrap *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_Wrap *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_Wrap_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_Wrap *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_Wrap_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_Wrap)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_CBCMAC : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_CBCMAC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_CBCMAC_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_CBCMAC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_CBCMAC *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_CBCMAC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_CBCMAC *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_CBCMAC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_CBCMAC)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_CFB8MAC : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_CFB8MAC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_CFB8MAC_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_CFB8MAC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_CFB8MAC *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_CFB8MAC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_CFB8MAC *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_CFB8MAC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_CFB8MAC)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1KeyFactory : LibOrgBouncycastleJcajceProviderSymmetricUtilPBESecretKeyFactory

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)arg1
                               withBoolean:(jboolean)arg2
                                   withInt:(jint)arg3
                                   withInt:(jint)arg4
                                   withInt:(jint)arg5
                                   withInt:(jint)arg6 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1KeyFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1KeyFactory_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1KeyFactory *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1KeyFactory *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1KeyFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1KeyFactory *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1KeyFactory_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1KeyFactory)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitKeyFactory : LibOrgBouncycastleJcajceProviderSymmetricUtilPBESecretKeyFactory

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)arg1
                               withBoolean:(jboolean)arg2
                                   withInt:(jint)arg3
                                   withInt:(jint)arg4
                                   withInt:(jint)arg5
                                   withInt:(jint)arg6 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitKeyFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitKeyFactory_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitKeyFactory *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitKeyFactory *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitKeyFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitKeyFactory *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitKeyFactory_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitKeyFactory)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitKeyFactory : LibOrgBouncycastleJcajceProviderSymmetricUtilPBESecretKeyFactory

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)arg1
                               withBoolean:(jboolean)arg2
                                   withInt:(jint)arg3
                                   withInt:(jint)arg4
                                   withInt:(jint)arg5
                                   withInt:(jint)arg6 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitKeyFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitKeyFactory_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitKeyFactory *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitKeyFactory *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitKeyFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitKeyFactory *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitKeyFactory_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitKeyFactory)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5AndRC2 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                          withBoolean:(jboolean)arg1
                                                              withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1
                                                              withInt:(jint)arg2
                                                              withInt:(jint)arg3
                                                              withInt:(jint)arg4 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                  withBoolean:(jboolean)arg1
                                                                      withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                      withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0
                                                                   withBoolean:(jboolean)arg1
                                                                       withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider:(id<LibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5AndRC2)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5AndRC2_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5AndRC2 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5AndRC2 *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5AndRC2_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5AndRC2 *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5AndRC2_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5AndRC2)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1AndRC2 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                          withBoolean:(jboolean)arg1
                                                              withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1
                                                              withInt:(jint)arg2
                                                              withInt:(jint)arg3
                                                              withInt:(jint)arg4 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                  withBoolean:(jboolean)arg1
                                                                      withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                      withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0
                                                                   withBoolean:(jboolean)arg1
                                                                       withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider:(id<LibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1AndRC2)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1AndRC2_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1AndRC2 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1AndRC2 *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1AndRC2_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1AndRC2 *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1AndRC2_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHA1AndRC2)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitRC2 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                          withBoolean:(jboolean)arg1
                                                              withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1
                                                              withInt:(jint)arg2
                                                              withInt:(jint)arg3
                                                              withInt:(jint)arg4 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                  withBoolean:(jboolean)arg1
                                                                      withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                      withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0
                                                                   withBoolean:(jboolean)arg1
                                                                       withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider:(id<LibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitRC2)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitRC2_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitRC2 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitRC2 *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitRC2_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitRC2 *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitRC2_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd128BitRC2)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitRC2 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                          withBoolean:(jboolean)arg1
                                                              withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1
                                                              withInt:(jint)arg2
                                                              withInt:(jint)arg3
                                                              withInt:(jint)arg4 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                  withBoolean:(jboolean)arg1
                                                                      withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                      withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0
                                                                   withBoolean:(jboolean)arg1
                                                                       withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider:(id<LibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitRC2)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitRC2_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitRC2 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitRC2 *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitRC2_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitRC2 *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitRC2_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithSHAAnd40BitRC2)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD2KeyFactory : LibOrgBouncycastleJcajceProviderSymmetricUtilPBESecretKeyFactory

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)arg1
                               withBoolean:(jboolean)arg2
                                   withInt:(jint)arg3
                                   withInt:(jint)arg4
                                   withInt:(jint)arg5
                                   withInt:(jint)arg6 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD2KeyFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD2KeyFactory_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD2KeyFactory *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD2KeyFactory *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD2KeyFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD2KeyFactory *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD2KeyFactory_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD2KeyFactory)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5KeyFactory : LibOrgBouncycastleJcajceProviderSymmetricUtilPBESecretKeyFactory

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)arg1
                               withBoolean:(jboolean)arg2
                                   withInt:(jint)arg3
                                   withInt:(jint)arg4
                                   withInt:(jint)arg5
                                   withInt:(jint)arg6 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5KeyFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5KeyFactory_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5KeyFactory *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5KeyFactory *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5KeyFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5KeyFactory *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5KeyFactory_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_PBEWithMD5KeyFactory)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParamGen : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator {
 @public
  JavaxCryptoSpecRC2ParameterSpec *spec_;
}

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (JavaSecurityAlgorithmParameters *)engineGenerateParameters;

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)genParamSpec
                                withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParamGen)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParamGen, spec_, JavaxCryptoSpecRC2ParameterSpec *)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParamGen_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParamGen *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParamGen *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParamGen_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParamGen *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParamGen_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParamGen)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_KeyGenerator : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_KeyGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_KeyGenerator_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_KeyGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_KeyGenerator *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_KeyGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_KeyGenerator *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_KeyGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_KeyGenerator)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParams : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameters

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (IOSByteArray *)engineGetEncoded;

- (IOSByteArray *)engineGetEncodedWithNSString:(NSString *)format;

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)paramSpec;

- (void)engineInitWithByteArray:(IOSByteArray *)params;

- (void)engineInitWithByteArray:(IOSByteArray *)params
                   withNSString:(NSString *)format;

- (NSString *)engineToString;

- (id<JavaSecuritySpecAlgorithmParameterSpec>)localEngineGetParameterSpecWithIOSClass:(IOSClass *)paramSpec;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParams)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParams_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParams *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParams *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParams_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParams *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParams_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_AlgParams)

@interface LibOrgBouncycastleJcajceProviderSymmetricRC2_Mappings : LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricRC2_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricRC2_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricRC2_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricRC2_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricRC2_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricRC2_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricRC2_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RC2_H
