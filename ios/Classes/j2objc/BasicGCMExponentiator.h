//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/gcm/BasicGCMExponentiator.java
//

#ifndef BasicGCMExponentiator_H
#define BasicGCMExponentiator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "GCMExponentiator.h"
#include "J2ObjC_header.h"

@class IOSByteArray;

@interface LibOrgBouncycastleCryptoModesGcmBasicGCMExponentiator : NSObject < LibOrgBouncycastleCryptoModesGcmGCMExponentiator >

#pragma mark Public

- (instancetype __nonnull)init;

- (void)exponentiateXWithLong:(jlong)pow
                withByteArray:(IOSByteArray *)output;

- (void)init__WithByteArray:(IOSByteArray *)x OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoModesGcmBasicGCMExponentiator)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesGcmBasicGCMExponentiator_init(LibOrgBouncycastleCryptoModesGcmBasicGCMExponentiator *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesGcmBasicGCMExponentiator *new_LibOrgBouncycastleCryptoModesGcmBasicGCMExponentiator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesGcmBasicGCMExponentiator *create_LibOrgBouncycastleCryptoModesGcmBasicGCMExponentiator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoModesGcmBasicGCMExponentiator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BasicGCMExponentiator_H