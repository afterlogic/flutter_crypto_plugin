//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/kgcm/BasicKGCMMultiplier_256.java
//

#ifndef BasicKGCMMultiplier_256_H
#define BasicKGCMMultiplier_256_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "KGCMMultiplier.h"

@class IOSLongArray;

@interface LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_256 : NSObject < LibOrgBouncycastleCryptoModesKgcmKGCMMultiplier >

#pragma mark Public

- (instancetype __nonnull)init;

- (void)init__WithLongArray:(IOSLongArray *)H OBJC_METHOD_FAMILY_NONE;

- (void)multiplyHWithLongArray:(IOSLongArray *)z;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_256)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_256_init(LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_256 *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_256 *new_LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_256 *create_LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_256)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BasicKGCMMultiplier_256_H