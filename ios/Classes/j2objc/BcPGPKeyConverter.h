//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/bc/BcPGPKeyConverter.java
//

#ifndef BcPGPKeyConverter_H
#define BcPGPKeyConverter_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaUtilDate;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@class LibOrgBouncycastleOpenpgpPGPPrivateKey;
@class LibOrgBouncycastleOpenpgpPGPPublicKey;
@protocol LibOrgBouncycastleOpenpgpPGPAlgorithmParameters;

@interface LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleOpenpgpPGPPrivateKey *)getPGPPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey
                                             withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privKey;

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPGPPublicKeyWithInt:(jint)algorithm
              withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters:(id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters>)algorithmParameters
         withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)pubKey
                                                 withJavaUtilDate:(JavaUtilDate *)time;

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPrivateKey:(LibOrgBouncycastleOpenpgpPGPPrivateKey *)privKey;

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)publicKey;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter_init(LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter *self);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter *new_LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter *create_LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BcPGPKeyConverter_H