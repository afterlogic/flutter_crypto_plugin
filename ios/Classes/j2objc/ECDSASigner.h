//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/ECDSASigner.java
//

#ifndef ECDSASigner_H
#define ECDSASigner_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "DSAExt.h"
#include "ECConstants.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSObjectArray;
@class JavaMathBigInteger;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleMathEcECFieldElement;
@class LibOrgBouncycastleMathEcECPoint;
@protocol LibOrgBouncycastleCryptoCipherParameters;
@protocol LibOrgBouncycastleCryptoSignersDSAKCalculator;
@protocol LibOrgBouncycastleMathEcECMultiplier;

@interface LibOrgBouncycastleCryptoSignersECDSASigner : NSObject < LibOrgBouncycastleMathEcECConstants, LibOrgBouncycastleCryptoDSAExt >

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoSignersDSAKCalculator:(id<LibOrgBouncycastleCryptoSignersDSAKCalculator>)kCalculator;

- (IOSObjectArray *)generateSignatureWithByteArray:(IOSByteArray *)message;

- (JavaMathBigInteger *)getOrder;

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                  withJavaMathBigInteger:(JavaMathBigInteger *)r
                  withJavaMathBigInteger:(JavaMathBigInteger *)s;

#pragma mark Protected

- (JavaMathBigInteger *)calculateEWithJavaMathBigInteger:(JavaMathBigInteger *)n
                                           withByteArray:(IOSByteArray *)message;

- (id<LibOrgBouncycastleMathEcECMultiplier>)createBasePointMultiplier;

- (LibOrgBouncycastleMathEcECFieldElement *)getDenominatorWithInt:(jint)coordinateSystem
                              withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p;

- (JavaSecuritySecureRandom *)initSecureRandomWithBoolean:(jboolean)needed
                             withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)provided OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoSignersECDSASigner)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersECDSASigner_init(LibOrgBouncycastleCryptoSignersECDSASigner *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersECDSASigner *new_LibOrgBouncycastleCryptoSignersECDSASigner_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersECDSASigner *create_LibOrgBouncycastleCryptoSignersECDSASigner_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersECDSASigner_initWithLibOrgBouncycastleCryptoSignersDSAKCalculator_(LibOrgBouncycastleCryptoSignersECDSASigner *self, id<LibOrgBouncycastleCryptoSignersDSAKCalculator> kCalculator);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersECDSASigner *new_LibOrgBouncycastleCryptoSignersECDSASigner_initWithLibOrgBouncycastleCryptoSignersDSAKCalculator_(id<LibOrgBouncycastleCryptoSignersDSAKCalculator> kCalculator) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersECDSASigner *create_LibOrgBouncycastleCryptoSignersECDSASigner_initWithLibOrgBouncycastleCryptoSignersDSAKCalculator_(id<LibOrgBouncycastleCryptoSignersDSAKCalculator> kCalculator);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersECDSASigner)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECDSASigner_H
