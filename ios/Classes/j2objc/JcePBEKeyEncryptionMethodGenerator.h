//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/jcajce/JcePBEKeyEncryptionMethodGenerator.java
//

#ifndef JcePBEKeyEncryptionMethodGenerator_H
#define JcePBEKeyEncryptionMethodGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PBEKeyEncryptionMethodGenerator.h"

@class IOSByteArray;
@class IOSCharArray;
@class JavaSecurityProvider;
@class JavaSecuritySecureRandom;
@protocol LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator;

@interface LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator : LibOrgBouncycastleOpenpgpOperatorPBEKeyEncryptionMethodGenerator

#pragma mark Public

- (instancetype __nonnull)initWithCharArray:(IOSCharArray *)passPhrase;

- (instancetype __nonnull)initWithCharArray:(IOSCharArray *)passPhrase
                                    withInt:(jint)s2kCount;

- (instancetype __nonnull)initWithCharArray:(IOSCharArray *)passPhrase
withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)s2kDigestCalculator;

- (instancetype __nonnull)initWithCharArray:(IOSCharArray *)passPhrase
withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)s2kDigestCalculator
                                    withInt:(jint)s2kCount;

- (LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *)setProviderWithJavaSecurityProvider:(JavaSecurityProvider *)provider;

- (LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *)setProviderWithNSString:(NSString *)providerName;

- (LibOrgBouncycastleOpenpgpOperatorPBEKeyEncryptionMethodGenerator *)setSecureRandomWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

#pragma mark Protected

- (IOSByteArray *)encryptSessionInfoWithInt:(jint)encAlgorithm
                              withByteArray:(IOSByteArray *)key
                              withByteArray:(IOSByteArray *)sessionInfo;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_(LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *self, IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_(IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_(IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator_initWithCharArray_(LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *self, IOSCharArray *passPhrase);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator_initWithCharArray_(IOSCharArray *passPhrase) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator_initWithCharArray_(IOSCharArray *passPhrase);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_(LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *self, IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, jint s2kCount);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_(IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, jint s2kCount) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_(IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, jint s2kCount);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator_initWithCharArray_withInt_(LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *self, IOSCharArray *passPhrase, jint s2kCount);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator_initWithCharArray_withInt_(IOSCharArray *passPhrase, jint s2kCount) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator_initWithCharArray_withInt_(IOSCharArray *passPhrase, jint s2kCount);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEKeyEncryptionMethodGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcePBEKeyEncryptionMethodGenerator_H