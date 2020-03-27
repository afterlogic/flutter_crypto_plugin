//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecP384R1Field.java
//

#ifndef SecP384R1Field_H
#define SecP384R1Field_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSIntArray;
@class JavaMathBigInteger;

@interface LibOrgBouncycastleMathEcCustomSecSecP384R1Field : NSObject
@property (readonly, class) IOSIntArray *P NS_SWIFT_NAME(P);
@property (readonly, class) IOSIntArray *PExt NS_SWIFT_NAME(PExt);

+ (IOSIntArray *)P;

+ (IOSIntArray *)PExt;

#pragma mark Public

- (instancetype __nonnull)init;

+ (void)addWithIntArray:(IOSIntArray *)x
           withIntArray:(IOSIntArray *)y
           withIntArray:(IOSIntArray *)z;

+ (void)addExtWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)yy
              withIntArray:(IOSIntArray *)zz;

+ (void)addOneWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z;

+ (IOSIntArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x;

+ (void)halfWithIntArray:(IOSIntArray *)x
            withIntArray:(IOSIntArray *)z;

+ (void)multiplyWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z;

+ (void)negateWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z;

+ (void)reduceWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)z;

+ (void)reduce32WithInt:(jint)x
           withIntArray:(IOSIntArray *)z;

+ (void)squareWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z;

+ (void)squareNWithIntArray:(IOSIntArray *)x
                    withInt:(jint)n
               withIntArray:(IOSIntArray *)z;

+ (void)subtractWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z;

+ (void)subtractExtWithIntArray:(IOSIntArray *)xx
                   withIntArray:(IOSIntArray *)yy
                   withIntArray:(IOSIntArray *)zz;

+ (void)twiceWithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)z;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleMathEcCustomSecSecP384R1Field)

inline IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP384R1Field_get_P(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP384R1Field_P;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleMathEcCustomSecSecP384R1Field, P, IOSIntArray *)

inline IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP384R1Field_get_PExt(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP384R1Field_PExt;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleMathEcCustomSecSecP384R1Field, PExt, IOSIntArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_init(LibOrgBouncycastleMathEcCustomSecSecP384R1Field *self);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecP384R1Field *new_LibOrgBouncycastleMathEcCustomSecSecP384R1Field_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecP384R1Field *create_LibOrgBouncycastleMathEcCustomSecSecP384R1Field_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_addWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_addExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_addOneWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP384R1Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_halfWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_negateWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_reduceWithIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_reduce32WithInt_withIntArray_(jint x, IOSIntArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_squareWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_squareNWithIntArray_withInt_withIntArray_(IOSIntArray *x, jint n, IOSIntArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_subtractWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_subtractExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP384R1Field_twiceWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcCustomSecSecP384R1Field)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SecP384R1Field_H
