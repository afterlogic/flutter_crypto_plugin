//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/raw/Nat256.java
//

#ifndef Nat256_H
#define Nat256_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSIntArray;
@class IOSLongArray;
@class JavaMathBigInteger;

@interface LibOrgBouncycastleMathRawNat256 : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (jint)addWithIntArray:(IOSIntArray *)x
                withInt:(jint)xOff
           withIntArray:(IOSIntArray *)y
                withInt:(jint)yOff
           withIntArray:(IOSIntArray *)z
                withInt:(jint)zOff;

+ (jint)addWithIntArray:(IOSIntArray *)x
           withIntArray:(IOSIntArray *)y
           withIntArray:(IOSIntArray *)z;

+ (jint)addBothToWithIntArray:(IOSIntArray *)x
                      withInt:(jint)xOff
                 withIntArray:(IOSIntArray *)y
                      withInt:(jint)yOff
                 withIntArray:(IOSIntArray *)z
                      withInt:(jint)zOff;

+ (jint)addBothToWithIntArray:(IOSIntArray *)x
                 withIntArray:(IOSIntArray *)y
                 withIntArray:(IOSIntArray *)z;

+ (jint)addToWithIntArray:(IOSIntArray *)x
                  withInt:(jint)xOff
             withIntArray:(IOSIntArray *)z
                  withInt:(jint)zOff
                  withInt:(jint)cIn;

+ (jint)addToWithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)z;

+ (jint)addToEachOtherWithIntArray:(IOSIntArray *)u
                           withInt:(jint)uOff
                      withIntArray:(IOSIntArray *)v
                           withInt:(jint)vOff;

+ (void)copy__WithIntArray:(IOSIntArray *)x
                   withInt:(jint)xOff
              withIntArray:(IOSIntArray *)z
                   withInt:(jint)zOff OBJC_METHOD_FAMILY_NONE;

+ (void)copy__WithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z OBJC_METHOD_FAMILY_NONE;

+ (void)copy64WithLongArray:(IOSLongArray *)x
                    withInt:(jint)xOff
              withLongArray:(IOSLongArray *)z
                    withInt:(jint)zOff OBJC_METHOD_FAMILY_NONE;

+ (void)copy64WithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z OBJC_METHOD_FAMILY_NONE;

+ (IOSIntArray *)create;

+ (IOSLongArray *)create64;

+ (IOSIntArray *)createExt;

+ (IOSLongArray *)createExt64;

+ (jboolean)diffWithIntArray:(IOSIntArray *)x
                     withInt:(jint)xOff
                withIntArray:(IOSIntArray *)y
                     withInt:(jint)yOff
                withIntArray:(IOSIntArray *)z
                     withInt:(jint)zOff;

+ (jboolean)eqWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)y;

+ (jboolean)eq64WithLongArray:(IOSLongArray *)x
                withLongArray:(IOSLongArray *)y;

+ (IOSIntArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x;

+ (IOSLongArray *)fromBigInteger64WithJavaMathBigInteger:(JavaMathBigInteger *)x;

+ (jint)getBitWithIntArray:(IOSIntArray *)x
                   withInt:(jint)bit;

+ (jboolean)gteWithIntArray:(IOSIntArray *)x
                    withInt:(jint)xOff
               withIntArray:(IOSIntArray *)y
                    withInt:(jint)yOff;

+ (jboolean)gteWithIntArray:(IOSIntArray *)x
               withIntArray:(IOSIntArray *)y;

+ (jboolean)isOneWithIntArray:(IOSIntArray *)x;

+ (jboolean)isOne64WithLongArray:(IOSLongArray *)x;

+ (jboolean)isZeroWithIntArray:(IOSIntArray *)x;

+ (jboolean)isZero64WithLongArray:(IOSLongArray *)x;

+ (void)mulWithIntArray:(IOSIntArray *)x
                withInt:(jint)xOff
           withIntArray:(IOSIntArray *)y
                withInt:(jint)yOff
           withIntArray:(IOSIntArray *)zz
                withInt:(jint)zzOff;

+ (void)mulWithIntArray:(IOSIntArray *)x
           withIntArray:(IOSIntArray *)y
           withIntArray:(IOSIntArray *)zz;

+ (jlong)mul33AddWithInt:(jint)w
            withIntArray:(IOSIntArray *)x
                 withInt:(jint)xOff
            withIntArray:(IOSIntArray *)y
                 withInt:(jint)yOff
            withIntArray:(IOSIntArray *)z
                 withInt:(jint)zOff;

+ (jint)mul33DWordAddWithInt:(jint)x
                    withLong:(jlong)y
                withIntArray:(IOSIntArray *)z
                     withInt:(jint)zOff;

+ (jint)mul33WordAddWithInt:(jint)x
                    withInt:(jint)y
               withIntArray:(IOSIntArray *)z
                    withInt:(jint)zOff;

+ (jint)mulAddToWithIntArray:(IOSIntArray *)x
                     withInt:(jint)xOff
                withIntArray:(IOSIntArray *)y
                     withInt:(jint)yOff
                withIntArray:(IOSIntArray *)zz
                     withInt:(jint)zzOff;

+ (jint)mulAddToWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)zz;

+ (jint)mulByWordWithInt:(jint)x
            withIntArray:(IOSIntArray *)z;

+ (jint)mulByWordAddToWithInt:(jint)x
                 withIntArray:(IOSIntArray *)y
                 withIntArray:(IOSIntArray *)z;

+ (jint)mulWordWithInt:(jint)x
          withIntArray:(IOSIntArray *)y
          withIntArray:(IOSIntArray *)z
               withInt:(jint)zOff;

+ (jint)mulWordAddToWithInt:(jint)x
               withIntArray:(IOSIntArray *)y
                    withInt:(jint)yOff
               withIntArray:(IOSIntArray *)z
                    withInt:(jint)zOff;

+ (jint)mulWordDwordAddWithInt:(jint)x
                      withLong:(jlong)y
                  withIntArray:(IOSIntArray *)z
                       withInt:(jint)zOff;

+ (void)squareWithIntArray:(IOSIntArray *)x
                   withInt:(jint)xOff
              withIntArray:(IOSIntArray *)zz
                   withInt:(jint)zzOff;

+ (void)squareWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)zz;

+ (jint)subWithIntArray:(IOSIntArray *)x
                withInt:(jint)xOff
           withIntArray:(IOSIntArray *)y
                withInt:(jint)yOff
           withIntArray:(IOSIntArray *)z
                withInt:(jint)zOff;

+ (jint)subWithIntArray:(IOSIntArray *)x
           withIntArray:(IOSIntArray *)y
           withIntArray:(IOSIntArray *)z;

+ (jint)subBothFromWithIntArray:(IOSIntArray *)x
                   withIntArray:(IOSIntArray *)y
                   withIntArray:(IOSIntArray *)z;

+ (jint)subFromWithIntArray:(IOSIntArray *)x
                    withInt:(jint)xOff
               withIntArray:(IOSIntArray *)z
                    withInt:(jint)zOff;

+ (jint)subFromWithIntArray:(IOSIntArray *)x
               withIntArray:(IOSIntArray *)z;

+ (JavaMathBigInteger *)toBigIntegerWithIntArray:(IOSIntArray *)x;

+ (JavaMathBigInteger *)toBigInteger64WithLongArray:(IOSLongArray *)x;

+ (void)zeroWithIntArray:(IOSIntArray *)z;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathRawNat256)

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat256_init(LibOrgBouncycastleMathRawNat256 *self);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_addWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_addWithIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(IOSIntArray *x, jint xOff, IOSIntArray *y, jint yOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_addBothToWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_addBothToWithIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(IOSIntArray *x, jint xOff, IOSIntArray *y, jint yOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_addToWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_addToWithIntArray_withInt_withIntArray_withInt_withInt_(IOSIntArray *x, jint xOff, IOSIntArray *z, jint zOff, jint cIn);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_addToEachOtherWithIntArray_withInt_withIntArray_withInt_(IOSIntArray *u, jint uOff, IOSIntArray *v, jint vOff);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat256_copy__WithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat256_copy__WithIntArray_withInt_withIntArray_withInt_(IOSIntArray *x, jint xOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat256_copy64WithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat256_copy64WithLongArray_withInt_withLongArray_withInt_(IOSLongArray *x, jint xOff, IOSLongArray *z, jint zOff);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastleMathRawNat256_create(void);

FOUNDATION_EXPORT IOSLongArray *LibOrgBouncycastleMathRawNat256_create64(void);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastleMathRawNat256_createExt(void);

FOUNDATION_EXPORT IOSLongArray *LibOrgBouncycastleMathRawNat256_createExt64(void);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathRawNat256_diffWithIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(IOSIntArray *x, jint xOff, IOSIntArray *y, jint yOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathRawNat256_eqWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathRawNat256_eq64WithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastleMathRawNat256_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x);

FOUNDATION_EXPORT IOSLongArray *LibOrgBouncycastleMathRawNat256_fromBigInteger64WithJavaMathBigInteger_(JavaMathBigInteger *x);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_getBitWithIntArray_withInt_(IOSIntArray *x, jint bit);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathRawNat256_gteWithIntArray_withInt_withIntArray_withInt_(IOSIntArray *x, jint xOff, IOSIntArray *y, jint yOff);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathRawNat256_isOneWithIntArray_(IOSIntArray *x);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathRawNat256_isOne64WithLongArray_(IOSLongArray *x);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathRawNat256_isZeroWithIntArray_(IOSIntArray *x);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathRawNat256_isZero64WithLongArray_(IOSLongArray *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat256_mulWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *zz);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat256_mulWithIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(IOSIntArray *x, jint xOff, IOSIntArray *y, jint yOff, IOSIntArray *zz, jint zzOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_mulAddToWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *zz);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_mulAddToWithIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(IOSIntArray *x, jint xOff, IOSIntArray *y, jint yOff, IOSIntArray *zz, jint zzOff);

FOUNDATION_EXPORT jlong LibOrgBouncycastleMathRawNat256_mul33AddWithInt_withIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(jint w, IOSIntArray *x, jint xOff, IOSIntArray *y, jint yOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_mulByWordWithInt_withIntArray_(jint x, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_mulByWordAddToWithInt_withIntArray_withIntArray_(jint x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_mulWordAddToWithInt_withIntArray_withInt_withIntArray_withInt_(jint x, IOSIntArray *y, jint yOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_mul33DWordAddWithInt_withLong_withIntArray_withInt_(jint x, jlong y, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_mul33WordAddWithInt_withInt_withIntArray_withInt_(jint x, jint y, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_mulWordDwordAddWithInt_withLong_withIntArray_withInt_(jint x, jlong y, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_mulWordWithInt_withIntArray_withIntArray_withInt_(jint x, IOSIntArray *y, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat256_squareWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *zz);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat256_squareWithIntArray_withInt_withIntArray_withInt_(IOSIntArray *x, jint xOff, IOSIntArray *zz, jint zzOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_subWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_subWithIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(IOSIntArray *x, jint xOff, IOSIntArray *y, jint yOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_subBothFromWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_subFromWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat256_subFromWithIntArray_withInt_withIntArray_withInt_(IOSIntArray *x, jint xOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleMathRawNat256_toBigIntegerWithIntArray_(IOSIntArray *x);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleMathRawNat256_toBigInteger64WithLongArray_(IOSLongArray *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat256_zeroWithIntArray_(IOSIntArray *z);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathRawNat256)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Nat256_H
