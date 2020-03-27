//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/jpake/JPAKEUtil.java
//

#ifndef JPAKEUtil_H
#define JPAKEUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSCharArray;
@class IOSObjectArray;
@class JavaMathBigInteger;
@class JavaSecuritySecureRandom;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil : NSObject
@property (readonly, class) JavaMathBigInteger *ZERO NS_SWIFT_NAME(ZERO);
@property (readonly, class) JavaMathBigInteger *ONE NS_SWIFT_NAME(ONE);

+ (JavaMathBigInteger *)ZERO;

+ (JavaMathBigInteger *)ONE;

#pragma mark Public

- (instancetype __nonnull)init;

+ (JavaMathBigInteger *)calculateAWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                  withJavaMathBigInteger:(JavaMathBigInteger *)q
                                  withJavaMathBigInteger:(JavaMathBigInteger *)gA
                                  withJavaMathBigInteger:(JavaMathBigInteger *)x2s;

+ (JavaMathBigInteger *)calculateGAWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                   withJavaMathBigInteger:(JavaMathBigInteger *)gx1
                                   withJavaMathBigInteger:(JavaMathBigInteger *)gx3
                                   withJavaMathBigInteger:(JavaMathBigInteger *)gx4;

+ (JavaMathBigInteger *)calculateGxWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                   withJavaMathBigInteger:(JavaMathBigInteger *)g
                                   withJavaMathBigInteger:(JavaMathBigInteger *)x;

+ (JavaMathBigInteger *)calculateKeyingMaterialWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                               withJavaMathBigInteger:(JavaMathBigInteger *)q
                                               withJavaMathBigInteger:(JavaMathBigInteger *)gx4
                                               withJavaMathBigInteger:(JavaMathBigInteger *)x2
                                               withJavaMathBigInteger:(JavaMathBigInteger *)s
                                               withJavaMathBigInteger:(JavaMathBigInteger *)B;

+ (JavaMathBigInteger *)calculateMacTagWithNSString:(NSString *)participantId
                                       withNSString:(NSString *)partnerParticipantId
                             withJavaMathBigInteger:(JavaMathBigInteger *)gx1
                             withJavaMathBigInteger:(JavaMathBigInteger *)gx2
                             withJavaMathBigInteger:(JavaMathBigInteger *)gx3
                             withJavaMathBigInteger:(JavaMathBigInteger *)gx4
                             withJavaMathBigInteger:(JavaMathBigInteger *)keyingMaterial
                 withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

+ (JavaMathBigInteger *)calculateSWithCharArray:(IOSCharArray *)password;

+ (JavaMathBigInteger *)calculateX2sWithJavaMathBigInteger:(JavaMathBigInteger *)q
                                    withJavaMathBigInteger:(JavaMathBigInteger *)x2
                                    withJavaMathBigInteger:(JavaMathBigInteger *)s;

+ (IOSObjectArray *)calculateZeroKnowledgeProofWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                               withJavaMathBigInteger:(JavaMathBigInteger *)q
                                               withJavaMathBigInteger:(JavaMathBigInteger *)g
                                               withJavaMathBigInteger:(JavaMathBigInteger *)gx
                                               withJavaMathBigInteger:(JavaMathBigInteger *)x
                                                         withNSString:(NSString *)participantId
                                   withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

+ (JavaMathBigInteger *)generateX1WithJavaMathBigInteger:(JavaMathBigInteger *)q
                            withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

+ (JavaMathBigInteger *)generateX2WithJavaMathBigInteger:(JavaMathBigInteger *)q
                            withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

+ (void)validateGaWithJavaMathBigInteger:(JavaMathBigInteger *)ga;

+ (void)validateGx4WithJavaMathBigInteger:(JavaMathBigInteger *)gx4;

+ (void)validateMacTagWithNSString:(NSString *)participantId
                      withNSString:(NSString *)partnerParticipantId
            withJavaMathBigInteger:(JavaMathBigInteger *)gx1
            withJavaMathBigInteger:(JavaMathBigInteger *)gx2
            withJavaMathBigInteger:(JavaMathBigInteger *)gx3
            withJavaMathBigInteger:(JavaMathBigInteger *)gx4
            withJavaMathBigInteger:(JavaMathBigInteger *)keyingMaterial
withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
            withJavaMathBigInteger:(JavaMathBigInteger *)partnerMacTag;

+ (void)validateNotNullWithId:(id)object
                 withNSString:(NSString *)description_;

+ (void)validateParticipantIdsDifferWithNSString:(NSString *)participantId1
                                    withNSString:(NSString *)participantId2;

+ (void)validateParticipantIdsEqualWithNSString:(NSString *)expectedParticipantId
                                   withNSString:(NSString *)actualParticipantId;

+ (void)validateZeroKnowledgeProofWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                  withJavaMathBigInteger:(JavaMathBigInteger *)q
                                  withJavaMathBigInteger:(JavaMathBigInteger *)g
                                  withJavaMathBigInteger:(JavaMathBigInteger *)gx
                             withJavaMathBigIntegerArray:(IOSObjectArray *)zeroKnowledgeProof
                                            withNSString:(NSString *)participantId
                      withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_get_ZERO(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_ZERO;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil, ZERO, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_get_ONE(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_ONE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil, ONE, JavaMathBigInteger *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_init(LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil *new_LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil *create_LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_init(void);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_generateX1WithJavaMathBigInteger_withJavaSecuritySecureRandom_(JavaMathBigInteger *q, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_generateX2WithJavaMathBigInteger_withJavaSecuritySecureRandom_(JavaMathBigInteger *q, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_calculateSWithCharArray_(IOSCharArray *password);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_calculateGxWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *x);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_calculateGAWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *gx1, JavaMathBigInteger *gx3, JavaMathBigInteger *gx4);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_calculateX2sWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *x2, JavaMathBigInteger *s);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_calculateAWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *gA, JavaMathBigInteger *x2s);

FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_calculateZeroKnowledgeProofWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withNSString_withLibOrgBouncycastleCryptoDigest_withJavaSecuritySecureRandom_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g, JavaMathBigInteger *gx, JavaMathBigInteger *x, NSString *participantId, id<LibOrgBouncycastleCryptoDigest> digest, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_validateGx4WithJavaMathBigInteger_(JavaMathBigInteger *gx4);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_validateGaWithJavaMathBigInteger_(JavaMathBigInteger *ga);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_validateZeroKnowledgeProofWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigIntegerArray_withNSString_withLibOrgBouncycastleCryptoDigest_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g, JavaMathBigInteger *gx, IOSObjectArray *zeroKnowledgeProof, NSString *participantId, id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_calculateKeyingMaterialWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *gx4, JavaMathBigInteger *x2, JavaMathBigInteger *s, JavaMathBigInteger *B);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_validateParticipantIdsDifferWithNSString_withNSString_(NSString *participantId1, NSString *participantId2);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_validateParticipantIdsEqualWithNSString_withNSString_(NSString *expectedParticipantId, NSString *actualParticipantId);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_validateNotNullWithId_withNSString_(id object, NSString *description_);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_calculateMacTagWithNSString_withNSString_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleCryptoDigest_(NSString *participantId, NSString *partnerParticipantId, JavaMathBigInteger *gx1, JavaMathBigInteger *gx2, JavaMathBigInteger *gx3, JavaMathBigInteger *gx4, JavaMathBigInteger *keyingMaterial, id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_validateMacTagWithNSString_withNSString_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleCryptoDigest_withJavaMathBigInteger_(NSString *participantId, NSString *partnerParticipantId, JavaMathBigInteger *gx1, JavaMathBigInteger *gx2, JavaMathBigInteger *gx3, JavaMathBigInteger *gx4, JavaMathBigInteger *keyingMaterial, id<LibOrgBouncycastleCryptoDigest> digest, JavaMathBigInteger *partnerMacTag);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JPAKEUtil_H
