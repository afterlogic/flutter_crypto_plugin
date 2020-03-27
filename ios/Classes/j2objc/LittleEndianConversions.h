//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/linearalgebra/LittleEndianConversions.java
//

#ifndef LittleEndianConversions_H
#define LittleEndianConversions_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSIntArray;

@interface LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions : NSObject

#pragma mark Public

+ (IOSByteArray *)I2OSPWithInt:(jint)x;

+ (void)I2OSPWithInt:(jint)value
       withByteArray:(IOSByteArray *)output
             withInt:(jint)outOff;

+ (void)I2OSPWithInt:(jint)value
       withByteArray:(IOSByteArray *)output
             withInt:(jint)outOff
             withInt:(jint)outLen;

+ (IOSByteArray *)I2OSPWithLong:(jlong)input;

+ (void)I2OSPWithLong:(jlong)input
        withByteArray:(IOSByteArray *)output
              withInt:(jint)outOff;

+ (jint)OS2IPWithByteArray:(IOSByteArray *)input;

+ (jint)OS2IPWithByteArray:(IOSByteArray *)input
                   withInt:(jint)inOff;

+ (jint)OS2IPWithByteArray:(IOSByteArray *)input
                   withInt:(jint)inOff
                   withInt:(jint)inLen;

+ (jlong)OS2LIPWithByteArray:(IOSByteArray *)input
                     withInt:(jint)inOff;

+ (IOSByteArray *)toByteArrayWithIntArray:(IOSIntArray *)input
                                  withInt:(jint)outLen;

+ (IOSIntArray *)toIntArrayWithByteArray:(IOSByteArray *)input;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions)

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_OS2IPWithByteArray_(IOSByteArray *input);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_OS2IPWithByteArray_withInt_(IOSByteArray *input, jint inOff);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_OS2IPWithByteArray_withInt_withInt_(IOSByteArray *input, jint inOff, jint inLen);

FOUNDATION_EXPORT jlong LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_OS2LIPWithByteArray_withInt_(IOSByteArray *input, jint inOff);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_I2OSPWithInt_(jint x);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_I2OSPWithInt_withByteArray_withInt_(jint value, IOSByteArray *output, jint outOff);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_I2OSPWithInt_withByteArray_withInt_withInt_(jint value, IOSByteArray *output, jint outOff, jint outLen);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_I2OSPWithLong_(jlong input);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_I2OSPWithLong_withByteArray_withInt_(jlong input, IOSByteArray *output, jint outOff);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_toByteArrayWithIntArray_withInt_(IOSIntArray *input, jint outLen);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_toIntArrayWithByteArray_(IOSByteArray *input);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // LittleEndianConversions_H