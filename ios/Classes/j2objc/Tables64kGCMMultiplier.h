//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/gcm/Tables64kGCMMultiplier.java
//

#ifndef Tables64kGCMMultiplier_H
#define Tables64kGCMMultiplier_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "GCMMultiplier.h"
#include "J2ObjC_header.h"

@class IOSByteArray;

@interface LibOrgBouncycastleCryptoModesGcmTables64kGCMMultiplier : NSObject < LibOrgBouncycastleCryptoModesGcmGCMMultiplier >

#pragma mark Public

- (instancetype __nonnull)init;

- (void)init__WithByteArray:(IOSByteArray *)H OBJC_METHOD_FAMILY_NONE;

- (void)multiplyHWithByteArray:(IOSByteArray *)x;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoModesGcmTables64kGCMMultiplier)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesGcmTables64kGCMMultiplier_init(LibOrgBouncycastleCryptoModesGcmTables64kGCMMultiplier *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesGcmTables64kGCMMultiplier *new_LibOrgBouncycastleCryptoModesGcmTables64kGCMMultiplier_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesGcmTables64kGCMMultiplier *create_LibOrgBouncycastleCryptoModesGcmTables64kGCMMultiplier_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoModesGcmTables64kGCMMultiplier)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Tables64kGCMMultiplier_H