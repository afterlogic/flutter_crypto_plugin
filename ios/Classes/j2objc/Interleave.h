//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/raw/Interleave.java
//

#ifndef Interleave_H
#define Interleave_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSLongArray;

@interface LibOrgBouncycastleMathRawInterleave : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (jint)expand16to32WithInt:(jint)x;

+ (jlong)expand32to64WithInt:(jint)x;

+ (void)expand64To128WithLong:(jlong)x
                withLongArray:(IOSLongArray *)z
                      withInt:(jint)zOff;

+ (void)expand64To128RevWithLong:(jlong)x
                   withLongArray:(IOSLongArray *)z
                         withInt:(jint)zOff;

+ (jint)expand8to16WithInt:(jint)x;

+ (jint)shuffleWithInt:(jint)x;

+ (jlong)shuffleWithLong:(jlong)x;

+ (jint)shuffle2WithInt:(jint)x;

+ (jint)unshuffleWithInt:(jint)x;

+ (jlong)unshuffleWithLong:(jlong)x;

+ (jint)unshuffle2WithInt:(jint)x;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathRawInterleave)

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawInterleave_init(LibOrgBouncycastleMathRawInterleave *self);

FOUNDATION_EXPORT LibOrgBouncycastleMathRawInterleave *new_LibOrgBouncycastleMathRawInterleave_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathRawInterleave *create_LibOrgBouncycastleMathRawInterleave_init(void);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawInterleave_expand8to16WithInt_(jint x);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawInterleave_expand16to32WithInt_(jint x);

FOUNDATION_EXPORT jlong LibOrgBouncycastleMathRawInterleave_expand32to64WithInt_(jint x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawInterleave_expand64To128WithLong_withLongArray_withInt_(jlong x, IOSLongArray *z, jint zOff);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawInterleave_expand64To128RevWithLong_withLongArray_withInt_(jlong x, IOSLongArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawInterleave_shuffleWithInt_(jint x);

FOUNDATION_EXPORT jlong LibOrgBouncycastleMathRawInterleave_shuffleWithLong_(jlong x);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawInterleave_shuffle2WithInt_(jint x);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawInterleave_unshuffleWithInt_(jint x);

FOUNDATION_EXPORT jlong LibOrgBouncycastleMathRawInterleave_unshuffleWithLong_(jlong x);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawInterleave_unshuffle2WithInt_(jint x);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathRawInterleave)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Interleave_H