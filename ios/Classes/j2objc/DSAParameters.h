//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/DSAParameters.java
//

#ifndef DSAParameters_H
#define DSAParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "CipherParameters.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleCryptoParamsDSAValidationParameters;

@interface LibOrgBouncycastleCryptoParamsDSAParameters : NSObject < LibOrgBouncycastleCryptoCipherParameters >

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                              withJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)g;

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                              withJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)g
withLibOrgBouncycastleCryptoParamsDSAValidationParameters:(LibOrgBouncycastleCryptoParamsDSAValidationParameters *)params;

- (jboolean)isEqual:(id)obj;

- (JavaMathBigInteger *)getG;

- (JavaMathBigInteger *)getP;

- (JavaMathBigInteger *)getQ;

- (LibOrgBouncycastleCryptoParamsDSAValidationParameters *)getValidationParameters;

- (NSUInteger)hash;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsDSAParameters)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsDSAParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleCryptoParamsDSAParameters *self, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsDSAParameters *new_LibOrgBouncycastleCryptoParamsDSAParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsDSAParameters *create_LibOrgBouncycastleCryptoParamsDSAParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsDSAParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDSAValidationParameters_(LibOrgBouncycastleCryptoParamsDSAParameters *self, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g, LibOrgBouncycastleCryptoParamsDSAValidationParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsDSAParameters *new_LibOrgBouncycastleCryptoParamsDSAParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDSAValidationParameters_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g, LibOrgBouncycastleCryptoParamsDSAValidationParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsDSAParameters *create_LibOrgBouncycastleCryptoParamsDSAParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDSAValidationParameters_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g, LibOrgBouncycastleCryptoParamsDSAValidationParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsDSAParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DSAParameters_H