//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/kgcm/KGCMUtil_128.java
//

#ifndef KGCMUtil_128_H
#define KGCMUtil_128_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSLongArray;

@interface LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128 : NSObject
@property (readonly, class) jint SIZE NS_SWIFT_NAME(SIZE);

+ (jint)SIZE;

#pragma mark Public

- (instancetype __nonnull)init;

+ (void)addWithLongArray:(IOSLongArray *)x
           withLongArray:(IOSLongArray *)y
           withLongArray:(IOSLongArray *)z;

+ (void)copy__WithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z OBJC_METHOD_FAMILY_NONE;

+ (jboolean)equalWithLongArray:(IOSLongArray *)x
                 withLongArray:(IOSLongArray *)y;

+ (void)multiplyWithLongArray:(IOSLongArray *)x
                withLongArray:(IOSLongArray *)y
                withLongArray:(IOSLongArray *)z;

+ (void)multiplyXWithLongArray:(IOSLongArray *)x
                 withLongArray:(IOSLongArray *)z;

+ (void)multiplyX8WithLongArray:(IOSLongArray *)x
                  withLongArray:(IOSLongArray *)z;

+ (void)oneWithLongArray:(IOSLongArray *)z;

+ (void)squareWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z;

+ (void)xWithLongArray:(IOSLongArray *)z;

+ (void)zeroWithLongArray:(IOSLongArray *)z;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128)

inline jint LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_get_SIZE(void);
#define LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_SIZE 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128, SIZE, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_init(LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128 *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128 *new_LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128 *create_LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_addWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_copy__WithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_equalWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_multiplyWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_multiplyXWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_multiplyX8WithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_oneWithLongArray_(IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_squareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_xWithLongArray_(IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_zeroWithLongArray_(IOSLongArray *z);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KGCMUtil_128_H
