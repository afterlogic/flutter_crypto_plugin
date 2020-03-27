//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/rsa/RsaCipherSpi.java
//

#ifndef RsaCipherSpi_H
#define RsaCipherSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BaseCipherSpi.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaSecurityAlgorithmParameters;
@class JavaSecuritySecureRandom;
@class JavaxCryptoSpecOAEPParameterSpec;
@protocol JavaSecurityKey;
@protocol JavaSecuritySpecAlgorithmParameterSpec;
@protocol LibOrgBouncycastleCryptoAsymmetricBlockCipher;

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi : LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)engine;

- (instancetype __nonnull)initWithBoolean:(jboolean)publicKeyOnly
                              withBoolean:(jboolean)privateKeyOnly
withLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)engine;

- (instancetype __nonnull)initWithJavaxCryptoSpecOAEPParameterSpec:(JavaxCryptoSpecOAEPParameterSpec *)pSpec;

#pragma mark Protected

- (IOSByteArray *)engineDoFinalWithByteArray:(IOSByteArray *)input
                                     withInt:(jint)inputOffset
                                     withInt:(jint)inputLen;

- (jint)engineDoFinalWithByteArray:(IOSByteArray *)input
                           withInt:(jint)inputOffset
                           withInt:(jint)inputLen
                     withByteArray:(IOSByteArray *)output
                           withInt:(jint)outputOffset;

- (jint)engineGetBlockSize;

- (jint)engineGetKeySizeWithJavaSecurityKey:(id<JavaSecurityKey>)key;

- (jint)engineGetOutputSizeWithInt:(jint)inputLen;

- (JavaSecurityAlgorithmParameters *)engineGetParameters;

- (void)engineInitWithInt:(jint)opmode
      withJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecurityAlgorithmParameters:(JavaSecurityAlgorithmParameters *)params
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)engineInitWithInt:(jint)opmode
      withJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)engineInitWithInt:(jint)opmode
      withJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)engineSetModeWithNSString:(NSString *)mode;

- (void)engineSetPaddingWithNSString:(NSString *)padding;

- (IOSByteArray *)engineUpdateWithByteArray:(IOSByteArray *)input
                                    withInt:(jint)inputOffset
                                    withInt:(jint)inputLen;

- (jint)engineUpdateWithByteArray:(IOSByteArray *)input
                          withInt:(jint)inputOffset
                          withInt:(jint)inputLen
                    withByteArray:(IOSByteArray *)output
                          withInt:(jint)outputOffset;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi *self, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> engine);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> engine) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> engine);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_initWithJavaxCryptoSpecOAEPParameterSpec_(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi *self, JavaxCryptoSpecOAEPParameterSpec *pSpec);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_initWithJavaxCryptoSpecOAEPParameterSpec_(JavaxCryptoSpecOAEPParameterSpec *pSpec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_initWithJavaxCryptoSpecOAEPParameterSpec_(JavaxCryptoSpecOAEPParameterSpec *pSpec);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_initWithBoolean_withBoolean_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi *self, jboolean publicKeyOnly, jboolean privateKeyOnly, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> engine);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_initWithBoolean_withBoolean_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(jboolean publicKeyOnly, jboolean privateKeyOnly, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> engine) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_initWithBoolean_withBoolean_withLibOrgBouncycastleCryptoAsymmetricBlockCipher_(jboolean publicKeyOnly, jboolean privateKeyOnly, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> engine);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_NoPadding : LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0
                              withBoolean:(jboolean)arg1
withLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaxCryptoSpecOAEPParameterSpec:(JavaxCryptoSpecOAEPParameterSpec *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_NoPadding)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_NoPadding_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_NoPadding *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_NoPadding *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_NoPadding_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_NoPadding *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_NoPadding_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_NoPadding)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding : LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0
                              withBoolean:(jboolean)arg1
withLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaxCryptoSpecOAEPParameterSpec:(JavaxCryptoSpecOAEPParameterSpec *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PrivateOnly : LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0
                              withBoolean:(jboolean)arg1
withLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaxCryptoSpecOAEPParameterSpec:(JavaxCryptoSpecOAEPParameterSpec *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PrivateOnly)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PrivateOnly_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PrivateOnly *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PrivateOnly *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PrivateOnly_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PrivateOnly *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PrivateOnly_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PrivateOnly)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PublicOnly : LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0
                              withBoolean:(jboolean)arg1
withLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaxCryptoSpecOAEPParameterSpec:(JavaxCryptoSpecOAEPParameterSpec *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PublicOnly)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PublicOnly_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PublicOnly *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PublicOnly *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PublicOnly_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PublicOnly *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PublicOnly_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_PKCS1v1_5Padding_PublicOnly)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_OAEPPadding : LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0
                              withBoolean:(jboolean)arg1
withLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaxCryptoSpecOAEPParameterSpec:(JavaxCryptoSpecOAEPParameterSpec *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_OAEPPadding)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_OAEPPadding_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_OAEPPadding *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_OAEPPadding *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_OAEPPadding_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_OAEPPadding *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_OAEPPadding_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_OAEPPadding)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_ISO9796d1Padding : LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0
                              withBoolean:(jboolean)arg1
withLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaxCryptoSpecOAEPParameterSpec:(JavaxCryptoSpecOAEPParameterSpec *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_ISO9796d1Padding)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_ISO9796d1Padding_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_ISO9796d1Padding *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_ISO9796d1Padding *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_ISO9796d1Padding_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_ISO9796d1Padding *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_ISO9796d1Padding_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaCipherSpi_ISO9796d1Padding)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RsaCipherSpi_H
