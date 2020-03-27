//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/mceliece/BCMcElieceCCA2PrivateKey.java
//

#ifndef BCMcElieceCCA2PrivateKey_H
#define BCMcElieceCCA2PrivateKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/PrivateKey.h"

@class IOSByteArray;
@class IOSObjectArray;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@class LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PrivateKeyParameters;
@class LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix;
@class LibOrgBouncycastlePqcMathLinearalgebraGF2mField;
@class LibOrgBouncycastlePqcMathLinearalgebraPermutation;
@class LibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM;

@interface LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PrivateKey : NSObject < JavaSecurityPrivateKey >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PrivateKeyParameters:(LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PrivateKeyParameters *)params;

- (jboolean)isEqual:(id)other;

- (NSString *)getAlgorithm;

- (IOSByteArray *)getEncoded;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2mField *)getField;

- (NSString *)getFormat;

- (LibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM *)getGoppaPoly;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)getH;

- (jint)getK;

- (jint)getN;

- (LibOrgBouncycastlePqcMathLinearalgebraPermutation *)getP;

- (IOSObjectArray *)getQInv;

- (jint)getT;

- (NSUInteger)hash;

#pragma mark Package-Private

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getKeyParams;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PrivateKey)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PrivateKey_initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PrivateKeyParameters_(LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PrivateKey *self, LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PrivateKeyParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PrivateKey *new_LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PrivateKey_initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PrivateKeyParameters_(LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PrivateKeyParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PrivateKey *create_LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PrivateKey_initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PrivateKeyParameters_(LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PrivateKeyParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PrivateKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BCMcElieceCCA2PrivateKey_H