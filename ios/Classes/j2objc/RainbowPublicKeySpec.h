//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/spec/RainbowPublicKeySpec.java
//

#ifndef RainbowPublicKeySpec_H
#define RainbowPublicKeySpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/KeySpec.h"

@class IOSObjectArray;
@class IOSShortArray;

@interface LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec : NSObject < JavaSecuritySpecKeySpec >

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)docLength
                      withShortArray2:(IOSObjectArray *)coeffquadratic
                      withShortArray2:(IOSObjectArray *)coeffSingular
                       withShortArray:(IOSShortArray *)coeffScalar;

- (IOSObjectArray *)getCoeffQuadratic;

- (IOSShortArray *)getCoeffScalar;

- (IOSObjectArray *)getCoeffSingular;

- (jint)getDocLength;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec_initWithInt_withShortArray2_withShortArray2_withShortArray_(LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec *self, jint docLength, IOSObjectArray *coeffquadratic, IOSObjectArray *coeffSingular, IOSShortArray *coeffScalar);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec *new_LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec_initWithInt_withShortArray2_withShortArray2_withShortArray_(jint docLength, IOSObjectArray *coeffquadratic, IOSObjectArray *coeffSingular, IOSShortArray *coeffScalar) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec *create_LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec_initWithInt_withShortArray2_withShortArray2_withShortArray_(jint docLength, IOSObjectArray *coeffquadratic, IOSObjectArray *coeffSingular, IOSShortArray *coeffScalar);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceSpecRainbowPublicKeySpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RainbowPublicKeySpec_H
