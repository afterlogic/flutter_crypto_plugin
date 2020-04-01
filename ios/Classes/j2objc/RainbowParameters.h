//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/rainbow/RainbowParameters.java
//

#ifndef RainbowParameters_H
#define RainbowParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "CipherParameters.h"
#include "J2ObjC_header.h"

@class IOSIntArray;

@interface LibOrgBouncycastlePqcCryptoRainbowRainbowParameters : NSObject < LibOrgBouncycastleCryptoCipherParameters >

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithIntArray:(IOSIntArray *)vi;

- (jint)getDocLength;

- (jint)getNumOfLayers;

- (IOSIntArray *)getVi;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoRainbowRainbowParameters)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoRainbowRainbowParameters_init(LibOrgBouncycastlePqcCryptoRainbowRainbowParameters *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoRainbowRainbowParameters *new_LibOrgBouncycastlePqcCryptoRainbowRainbowParameters_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoRainbowRainbowParameters *create_LibOrgBouncycastlePqcCryptoRainbowRainbowParameters_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoRainbowRainbowParameters_initWithIntArray_(LibOrgBouncycastlePqcCryptoRainbowRainbowParameters *self, IOSIntArray *vi);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoRainbowRainbowParameters *new_LibOrgBouncycastlePqcCryptoRainbowRainbowParameters_initWithIntArray_(IOSIntArray *vi) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoRainbowRainbowParameters *create_LibOrgBouncycastlePqcCryptoRainbowRainbowParameters_initWithIntArray_(IOSIntArray *vi);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoRainbowRainbowParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RainbowParameters_H