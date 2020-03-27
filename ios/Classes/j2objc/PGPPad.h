//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/PGPPad.java
//

#ifndef PGPPad_H
#define PGPPad_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;

@interface LibOrgBouncycastleOpenpgpOperatorPGPPad : NSObject

#pragma mark Public

+ (IOSByteArray *)padSessionDataWithByteArray:(IOSByteArray *)sessionInfo;

+ (IOSByteArray *)unpadSessionDataWithByteArray:(IOSByteArray *)encoded;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorPGPPad)

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleOpenpgpOperatorPGPPad_padSessionDataWithByteArray_(IOSByteArray *sessionInfo);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleOpenpgpOperatorPGPPad_unpadSessionDataWithByteArray_(IOSByteArray *encoded);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorPGPPad)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPPad_H
