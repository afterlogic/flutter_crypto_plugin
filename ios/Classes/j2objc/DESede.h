//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/DESede.java
//

#ifndef DESede_H
#define DESede_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AlgorithmProvider.h"
#include "BaseAlgorithmParameterGenerator.h"
#include "BaseBlockCipher.h"
#include "BaseKeyGenerator.h"
#include "BaseMac.h"
#include "BaseSecretKeyFactory.h"
#include "BaseWrapCipher.h"
#include "DES.h"
#include "J2ObjC_header.h"

@class IOSClass;
@class JavaSecurityAlgorithmParameters;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleCryptoBufferedBlockCipher;
@class LibOrgBouncycastleCryptoCipherKeyGenerator;
@protocol JavaSecuritySpecAlgorithmParameterSpec;
@protocol JavaSecuritySpecKeySpec;
@protocol JavaxCryptoSecretKey;
@protocol LibOrgBouncycastleCryptoBlockCipher;
@protocol LibOrgBouncycastleCryptoMac;
@protocol LibOrgBouncycastleCryptoModesAEADBlockCipher;
@protocol LibOrgBouncycastleCryptoWrapper;
@protocol LibOrgBouncycastleJcajceProviderConfigConfigurableProvider;
@protocol LibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider;

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_ECB : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_ECB)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_ECB_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_ECB *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_ECB *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_ECB_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_ECB *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_ECB_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_ECB)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_CBC : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_CBC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_CBC_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_CBC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_CBC *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_CBC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_CBC *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_CBC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_CBC)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_DESedeCFB8 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_DESedeCFB8)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_DESedeCFB8_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_DESedeCFB8 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_DESedeCFB8 *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_DESedeCFB8_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_DESedeCFB8 *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_DESedeCFB8_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_DESedeCFB8)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64 *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64 *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64with7816d4 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64with7816d4)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64with7816d4_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64with7816d4 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64with7816d4 *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64with7816d4_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64with7816d4 *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64with7816d4_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_DESede64with7816d4)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_CBCMAC : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_CBCMAC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_CBCMAC_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_CBCMAC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_CBCMAC *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_CBCMAC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_CBCMAC *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_CBCMAC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_CBCMAC)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_CMAC : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_CMAC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_CMAC_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_CMAC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_CMAC *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_CMAC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_CMAC *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_CMAC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_CMAC)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_Wrap : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoWrapper:(id<LibOrgBouncycastleCryptoWrapper>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoWrapper:(id<LibOrgBouncycastleCryptoWrapper>)arg0
                                                          withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_Wrap)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_Wrap_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_Wrap *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_Wrap *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_Wrap_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_Wrap *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_Wrap_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_Wrap)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_RFC3211 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoWrapper:(id<LibOrgBouncycastleCryptoWrapper>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoWrapper:(id<LibOrgBouncycastleCryptoWrapper>)arg0
                                                          withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_RFC3211)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_RFC3211_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_RFC3211 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_RFC3211 *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_RFC3211_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_RFC3211 *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_RFC3211_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_RFC3211)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (id<JavaxCryptoSecretKey>)engineGenerateKey;

- (void)engineInitWithInt:(jint)keySize
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator3 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator3)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator3_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator3 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator3 *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator3_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator3 *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator3_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyGenerator3)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3Key : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3Key)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3Key_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3Key *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3Key *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3Key_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3Key *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3Key_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3Key)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2Key : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2Key)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2Key_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2Key *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2Key *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2Key_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2Key *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2Key_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2Key)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3KeyFactory : LibOrgBouncycastleJcajceProviderSymmetricDES_DESPBEKeyFactory

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3KeyFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3KeyFactory_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3KeyFactory *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3KeyFactory *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3KeyFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3KeyFactory *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3KeyFactory_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES3KeyFactory)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2KeyFactory : LibOrgBouncycastleJcajceProviderSymmetricDES_DESPBEKeyFactory

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2KeyFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2KeyFactory_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2KeyFactory *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2KeyFactory *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2KeyFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2KeyFactory *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2KeyFactory_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_PBEWithSHAAndDES2KeyFactory)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_AlgParamGen : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (JavaSecurityAlgorithmParameters *)engineGenerateParameters;

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)genParamSpec
                                withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_AlgParamGen)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_AlgParamGen_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_AlgParamGen *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_AlgParamGen *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_AlgParamGen_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_AlgParamGen *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_AlgParamGen_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_AlgParamGen)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyFactory : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseSecretKeyFactory

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (id<JavaxCryptoSecretKey>)engineGenerateSecretWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaxCryptoSecretKey:(id<JavaxCryptoSecretKey>)key
                                                           withIOSClass:(IOSClass *)keySpec;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyFactory_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyFactory *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyFactory *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyFactory *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyFactory_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_KeyFactory)

@interface LibOrgBouncycastleJcajceProviderSymmetricDESede_Mappings : LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricDESede_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricDESede_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricDESede_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricDESede_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricDESede_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricDESede_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricDESede_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DESede_H
