//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/GOST3410Signer.java
//

#ifndef GOST3410Signer_H
#define GOST3410Signer_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "DSAExt.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSObjectArray;
@class JavaMathBigInteger;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoParamsGOST3410KeyParameters;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoSignersGOST3410Signer : NSObject < LibOrgBouncycastleCryptoDSAExt > {
 @public
  LibOrgBouncycastleCryptoParamsGOST3410KeyParameters *key_;
  JavaSecuritySecureRandom *random_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (IOSObjectArray *)generateSignatureWithByteArray:(IOSByteArray *)message;

- (JavaMathBigInteger *)getOrder;

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                  withJavaMathBigInteger:(JavaMathBigInteger *)r
                  withJavaMathBigInteger:(JavaMathBigInteger *)s;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoSignersGOST3410Signer)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersGOST3410Signer, key_, LibOrgBouncycastleCryptoParamsGOST3410KeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersGOST3410Signer, random_, JavaSecuritySecureRandom *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersGOST3410Signer_init(LibOrgBouncycastleCryptoSignersGOST3410Signer *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersGOST3410Signer *new_LibOrgBouncycastleCryptoSignersGOST3410Signer_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersGOST3410Signer *create_LibOrgBouncycastleCryptoSignersGOST3410Signer_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersGOST3410Signer)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GOST3410Signer_H
