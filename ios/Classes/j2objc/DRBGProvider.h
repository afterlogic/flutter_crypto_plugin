//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/prng/DRBGProvider.java
//

#ifndef DRBGProvider_H
#define DRBGProvider_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@protocol LibOrgBouncycastleCryptoPrngDrbgSP80090DRBG;
@protocol LibOrgBouncycastleCryptoPrngEntropySource;

@protocol LibOrgBouncycastleCryptoPrngDRBGProvider < JavaObject >

- (id<LibOrgBouncycastleCryptoPrngDrbgSP80090DRBG>)getWithLibOrgBouncycastleCryptoPrngEntropySource:(id<LibOrgBouncycastleCryptoPrngEntropySource>)entropySource;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoPrngDRBGProvider)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoPrngDRBGProvider)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DRBGProvider_H