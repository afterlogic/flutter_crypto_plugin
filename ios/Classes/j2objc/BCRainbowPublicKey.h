//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/rainbow/BCRainbowPublicKey.java
//

#ifndef BCRainbowPublicKey_H
#define BCRainbowPublicKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/PublicKey.h"

@class IOSByteArray;
@class IOSObjectArray;
@class IOSShortArray;
@class LibOrgBouncycastlePqcCryptoRainbowRainbowPublicKeyParameters;
@class LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec;

@interface LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey : NSObject < JavaSecurityPublicKey >

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)docLength
                      withShortArray2:(IOSObjectArray *)coeffQuadratic
                      withShortArray2:(IOSObjectArray *)coeffSingular
                       withShortArray:(IOSShortArray *)coeffScalar;

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcCryptoRainbowRainbowPublicKeyParameters:(LibOrgBouncycastlePqcCryptoRainbowRainbowPublicKeyParameters *)params;

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec:(LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec *)keySpec;

- (jboolean)isEqual:(id)other;

- (NSString *)getAlgorithm;

- (IOSObjectArray *)getCoeffQuadratic;

- (IOSShortArray *)getCoeffScalar;

- (IOSObjectArray *)getCoeffSingular;

- (jint)getDocLength;

- (IOSByteArray *)getEncoded;

- (NSString *)getFormat;

- (NSUInteger)hash;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey_initWithInt_withShortArray2_withShortArray2_withShortArray_(LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey *self, jint docLength, IOSObjectArray *coeffQuadratic, IOSObjectArray *coeffSingular, IOSShortArray *coeffScalar);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey *new_LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey_initWithInt_withShortArray2_withShortArray2_withShortArray_(jint docLength, IOSObjectArray *coeffQuadratic, IOSObjectArray *coeffSingular, IOSShortArray *coeffScalar) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey *create_LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey_initWithInt_withShortArray2_withShortArray2_withShortArray_(jint docLength, IOSObjectArray *coeffQuadratic, IOSObjectArray *coeffSingular, IOSShortArray *coeffScalar);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey_initWithLibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec_(LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey *self, LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec *keySpec);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey *new_LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey_initWithLibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec_(LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec *keySpec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey *create_LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey_initWithLibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec_(LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec *keySpec);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey_initWithLibOrgBouncycastlePqcCryptoRainbowRainbowPublicKeyParameters_(LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey *self, LibOrgBouncycastlePqcCryptoRainbowRainbowPublicKeyParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey *new_LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey_initWithLibOrgBouncycastlePqcCryptoRainbowRainbowPublicKeyParameters_(LibOrgBouncycastlePqcCryptoRainbowRainbowPublicKeyParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey *create_LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey_initWithLibOrgBouncycastlePqcCryptoRainbowRainbowPublicKeyParameters_(LibOrgBouncycastlePqcCryptoRainbowRainbowPublicKeyParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderRainbowBCRainbowPublicKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BCRainbowPublicKey_H
