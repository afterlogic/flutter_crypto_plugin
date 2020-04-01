//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/PBESecretKeyEncryptor.java
//

#ifndef PBESecretKeyEncryptor_H
#define PBESecretKeyEncryptor_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSCharArray;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleBcpgS2K;
@protocol LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator;

@interface LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor : NSObject {
 @public
  jint encAlgorithm_;
  IOSCharArray *passPhrase_;
  id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator_;
  jint s2kCount_;
  LibOrgBouncycastleBcpgS2K *s2k_;
  JavaSecuritySecureRandom *random_;
}

#pragma mark Public

- (IOSByteArray *)encryptKeyDataWithByteArray:(IOSByteArray *)key
                                withByteArray:(IOSByteArray *)iv
                                withByteArray:(IOSByteArray *)keyData
                                      withInt:(jint)keyOff
                                      withInt:(jint)keyLen;

- (IOSByteArray *)encryptKeyDataWithByteArray:(IOSByteArray *)key
                                withByteArray:(IOSByteArray *)keyData
                                      withInt:(jint)keyOff
                                      withInt:(jint)keyLen;

- (IOSByteArray *)encryptKeyDataWithByteArray:(IOSByteArray *)keyData
                                      withInt:(jint)keyOff
                                      withInt:(jint)keyLen;

- (jint)getAlgorithm;

- (IOSByteArray *)getCipherIV;

- (jint)getHashAlgorithm;

- (IOSByteArray *)getKey;

- (LibOrgBouncycastleBcpgS2K *)getS2K;

#pragma mark Protected

- (instancetype __nonnull)initWithInt:(jint)encAlgorithm
withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)s2kDigestCalculator
                              withInt:(jint)s2kCount
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                        withCharArray:(IOSCharArray *)passPhrase;

- (instancetype __nonnull)initWithInt:(jint)encAlgorithm
withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)s2kDigestCalculator
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                        withCharArray:(IOSCharArray *)passPhrase;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor, passPhrase_, IOSCharArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor, s2kDigestCalculator_, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor, s2k_, LibOrgBouncycastleBcpgS2K *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor, random_, JavaSecuritySecureRandom *)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withJavaSecuritySecureRandom_withCharArray_(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *self, jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, JavaSecuritySecureRandom *random, IOSCharArray *passPhrase);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_withJavaSecuritySecureRandom_withCharArray_(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *self, jint encAlgorithm, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> s2kDigestCalculator, jint s2kCount, JavaSecuritySecureRandom *random, IOSCharArray *passPhrase);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PBESecretKeyEncryptor_H