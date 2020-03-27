//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/jcajce/OperatorHelper.java
//

#ifndef OperatorHelper_H
#define OperatorHelper_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaSecurityAlgorithmParameters;
@class JavaSecurityKeyFactory;
@class JavaSecurityKeyPairGenerator;
@class JavaSecurityMessageDigest;
@class JavaSecuritySignature;
@class JavaxCryptoCipher;
@class JavaxCryptoKeyAgreement;
@protocol LibOrgBouncycastleJcajceUtilJcaJceHelper;
@protocol LibOrgBouncycastleOpenpgpOperatorPGPDataDecryptor;

@interface LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper : NSObject

#pragma mark Public

- (JavaSecurityAlgorithmParameters *)createAlgorithmParametersWithNSString:(NSString *)algorithm;

- (JavaxCryptoKeyAgreement *)createKeyAgreementWithNSString:(NSString *)algorithm;

- (JavaSecurityKeyPairGenerator *)createKeyPairGeneratorWithNSString:(NSString *)algorithm;

- (JavaSecuritySignature *)createSignatureWithInt:(jint)keyAlgorithm
                                          withInt:(jint)hashAlgorithm;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajceUtilJcaJceHelper:(id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)helper;

- (JavaxCryptoCipher *)createCipherWithNSString:(NSString *)cipherName;

- (id<LibOrgBouncycastleOpenpgpOperatorPGPDataDecryptor>)createDataDecryptorWithBoolean:(jboolean)withIntegrityPacket
                                                                                withInt:(jint)encAlgorithm
                                                                          withByteArray:(IOSByteArray *)key;

- (JavaSecurityMessageDigest *)createDigestWithInt:(jint)algorithm;

- (JavaSecurityKeyFactory *)createKeyFactoryWithNSString:(NSString *)algorithm;

- (JavaxCryptoCipher *)createKeyWrapperWithInt:(jint)encAlgorithm;

- (JavaxCryptoCipher *)createPublicKeyCipherWithInt:(jint)encAlgorithm;

- (JavaxCryptoCipher *)createStreamCipherWithInt:(jint)encAlgorithm
                                     withBoolean:(jboolean)withIntegrityPacket;

- (NSString *)getDigestNameWithInt:(jint)hashAlgorithm;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper *self, id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper *new_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper *create_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // OperatorHelper_H