//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/util/BaseCipherSpi.java
//

#ifndef BaseCipherSpi_H
#define BaseCipherSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/io/ByteArrayOutputStream.h"
#include "javax/crypto/CipherSpi.h"

@class IOSByteArray;
@class JavaSecurityAlgorithmParameters;
@protocol JavaSecurityKey;
@protocol LibOrgBouncycastleCryptoWrapper;

@interface LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi : JavaxCryptoCipherSpi {
 @public
  JavaSecurityAlgorithmParameters *engineParams_;
  id<LibOrgBouncycastleCryptoWrapper> wrapEngine_;
}

#pragma mark Protected

- (instancetype __nonnull)init;

- (JavaSecurityAlgorithmParameters *)createParametersInstanceWithNSString:(NSString *)algorithm;

- (jint)engineGetBlockSize;

- (IOSByteArray *)engineGetIV;

- (jint)engineGetKeySizeWithJavaSecurityKey:(id<JavaSecurityKey>)key;

- (jint)engineGetOutputSizeWithInt:(jint)inputLen;

- (JavaSecurityAlgorithmParameters *)engineGetParameters;

- (void)engineSetModeWithNSString:(NSString *)mode;

- (void)engineSetPaddingWithNSString:(NSString *)padding;

- (id<JavaSecurityKey>)engineUnwrapWithByteArray:(IOSByteArray *)wrappedKey
                                    withNSString:(NSString *)wrappedKeyAlgorithm
                                         withInt:(jint)wrappedKeyType;

- (IOSByteArray *)engineWrapWithJavaSecurityKey:(id<JavaSecurityKey>)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi, engineParams_, JavaSecurityAlgorithmParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi, wrapEngine_, id<LibOrgBouncycastleCryptoWrapper>)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi_init(LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi *self);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi)

@interface LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi_ErasableOutputStream : JavaIoByteArrayOutputStream

#pragma mark Public

- (instancetype __nonnull)init;

- (void)erase;

- (IOSByteArray *)getBuf;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi_ErasableOutputStream)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi_ErasableOutputStream_init(LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi_ErasableOutputStream *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi_ErasableOutputStream *new_LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi_ErasableOutputStream_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi_ErasableOutputStream *create_LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi_ErasableOutputStream_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseCipherSpi_ErasableOutputStream)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BaseCipherSpi_H
