//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/mceliece/McElieceCCA2KeysToParams.java
//

#ifndef McElieceCCA2KeysToParams_H
#define McElieceCCA2KeysToParams_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;

@interface LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeysToParams : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePrivateKeyParameterWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key;

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePublicKeyParameterWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeysToParams)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeysToParams_init(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeysToParams *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeysToParams *new_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeysToParams_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeysToParams *create_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeysToParams_init(void);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeysToParams_generatePublicKeyParameterWithJavaSecurityPublicKey_(id<JavaSecurityPublicKey> key);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeysToParams_generatePrivateKeyParameterWithJavaSecurityPrivateKey_(id<JavaSecurityPrivateKey> key);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeysToParams)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // McElieceCCA2KeysToParams_H