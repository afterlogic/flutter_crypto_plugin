//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/field/FiniteField.java
//

#ifndef FiniteField_H
#define FiniteField_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaMathBigInteger;

@protocol LibOrgBouncycastleMathFieldFiniteField < JavaObject >

- (JavaMathBigInteger *)getCharacteristic;

- (jint)getDimension;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathFieldFiniteField)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathFieldFiniteField)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // FiniteField_H