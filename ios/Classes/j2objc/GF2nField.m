//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/linearalgebra/GF2nField.java
//

#include "GF2nElement.h"
#include "GF2nField.h"
#include "GF2nONBElement.h"
#include "GF2nONBField.h"
#include "GF2nPolynomialElement.h"
#include "GF2nPolynomialField.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "PqcMathGF2Polynomial.h"
#include "java/lang/RuntimeException.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"
#include "java/util/Vector.h"

@implementation LibOrgBouncycastlePqcMathLinearalgebraGF2nField

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  LibOrgBouncycastlePqcMathLinearalgebraGF2nField_initWithJavaSecuritySecureRandom_(self, random);
  return self;
}

- (jint)getDegree {
  return mDegree_;
}

- (LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *)getFieldPolynomial {
  if (fieldPolynomial_ == nil) {
    [self computeFieldPolynomial];
  }
  return new_LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_initWithLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_(fieldPolynomial_);
}

- (jboolean)isEqual:(id)other {
  if (other == nil || !([other isKindOfClass:[LibOrgBouncycastlePqcMathLinearalgebraGF2nField class]])) {
    return false;
  }
  LibOrgBouncycastlePqcMathLinearalgebraGF2nField *otherField = (LibOrgBouncycastlePqcMathLinearalgebraGF2nField *) cast_chk(other, [LibOrgBouncycastlePqcMathLinearalgebraGF2nField class]);
  if (otherField->mDegree_ != mDegree_) {
    return false;
  }
  if (![((LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *) nil_chk(fieldPolynomial_)) isEqual:otherField->fieldPolynomial_]) {
    return false;
  }
  if (([self isKindOfClass:[LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField class]]) && !([otherField isKindOfClass:[LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField class]])) {
    return false;
  }
  if (([self isKindOfClass:[LibOrgBouncycastlePqcMathLinearalgebraGF2nONBField class]]) && !([otherField isKindOfClass:[LibOrgBouncycastlePqcMathLinearalgebraGF2nONBField class]])) {
    return false;
  }
  return true;
}

- (NSUInteger)hash {
  return mDegree_ + ((jint) [((LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *) nil_chk(fieldPolynomial_)) hash]);
}

- (LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *)getRandomRootWithLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial:(LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *)B0FieldPolynomial {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

- (void)computeCOBMatrixWithLibOrgBouncycastlePqcMathLinearalgebraGF2nField:(LibOrgBouncycastlePqcMathLinearalgebraGF2nField *)B1 {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

- (void)computeFieldPolynomial {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

- (IOSObjectArray *)invertMatrixWithLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2PolynomialArray:(IOSObjectArray *)matrix {
  IOSObjectArray *a = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(matrix))->size_ type:LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_class_()];
  IOSObjectArray *inv = [IOSObjectArray newArrayWithLength:matrix->size_ type:LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_class_()];
  LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *dummy;
  jint i;
  jint j;
  for (i = 0; i < mDegree_; i++) {
    (void) IOSObjectArray_SetAndConsume(a, i, new_LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_initWithLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_(IOSObjectArray_Get(matrix, i)));
    (void) IOSObjectArray_SetAndConsume(inv, i, new_LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_initWithInt_(mDegree_));
    [((LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *) nil_chk(IOSObjectArray_Get(inv, i))) setBitWithInt:mDegree_ - 1 - i];
  }
  for (i = 0; i < mDegree_ - 1; i++) {
    j = i;
    while ((j < mDegree_) && ![((LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *) nil_chk(IOSObjectArray_Get(a, j))) testBitWithInt:mDegree_ - 1 - i]) {
      j++;
    }
    if (j >= mDegree_) {
      @throw new_JavaLangRuntimeException_initWithNSString_(@"GF2nField.invertMatrix: Matrix cannot be inverted!");
    }
    if (i != j) {
      dummy = IOSObjectArray_Get(a, i);
      (void) IOSObjectArray_Set(a, i, IOSObjectArray_Get(a, j));
      (void) IOSObjectArray_Set(a, j, dummy);
      dummy = IOSObjectArray_Get(inv, i);
      (void) IOSObjectArray_Set(inv, i, IOSObjectArray_Get(inv, j));
      (void) IOSObjectArray_Set(inv, j, dummy);
    }
    for (j = i + 1; j < mDegree_; j++) {
      if ([((LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *) nil_chk(IOSObjectArray_Get(a, j))) testBitWithInt:mDegree_ - 1 - i]) {
        [((LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *) nil_chk(IOSObjectArray_Get(a, j))) addToThisWithLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial:IOSObjectArray_Get(a, i)];
        [((LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *) nil_chk(IOSObjectArray_Get(inv, j))) addToThisWithLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial:IOSObjectArray_Get(inv, i)];
      }
    }
  }
  for (i = mDegree_ - 1; i > 0; i--) {
    for (j = i - 1; j >= 0; j--) {
      if ([((LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *) nil_chk(IOSObjectArray_Get(a, j))) testBitWithInt:mDegree_ - 1 - i]) {
        [((LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *) nil_chk(IOSObjectArray_Get(a, j))) addToThisWithLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial:IOSObjectArray_Get(a, i)];
        [((LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *) nil_chk(IOSObjectArray_Get(inv, j))) addToThisWithLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial:IOSObjectArray_Get(inv, i)];
      }
    }
  }
  return inv;
}

- (LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *)convertWithLibOrgBouncycastlePqcMathLinearalgebraGF2nElement:(LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *)elem
                                                                withLibOrgBouncycastlePqcMathLinearalgebraGF2nField:(LibOrgBouncycastlePqcMathLinearalgebraGF2nField *)basis {
  if (basis == self) {
    return (LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *) cast_chk([((LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *) nil_chk(elem)) java_clone], [LibOrgBouncycastlePqcMathLinearalgebraGF2nElement class]);
  }
  if ([((LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *) nil_chk(fieldPolynomial_)) isEqual:((LibOrgBouncycastlePqcMathLinearalgebraGF2nField *) nil_chk(basis))->fieldPolynomial_]) {
    return (LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *) cast_chk([((LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *) nil_chk(elem)) java_clone], [LibOrgBouncycastlePqcMathLinearalgebraGF2nElement class]);
  }
  if (mDegree_ != basis->mDegree_) {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"GF2nField.convert: B1 has a different degree and thus cannot be coverted to!");
  }
  jint i;
  IOSObjectArray *COBMatrix;
  i = [((JavaUtilVector *) nil_chk(fields_)) indexOfWithId:basis];
  if (i == -1) {
    [self computeCOBMatrixWithLibOrgBouncycastlePqcMathLinearalgebraGF2nField:basis];
    i = [((JavaUtilVector *) nil_chk(fields_)) indexOfWithId:basis];
  }
  COBMatrix = (IOSObjectArray *) cast_check([((JavaUtilVector *) nil_chk(matrices_)) elementAtWithInt:i], IOSClass_arrayType(LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_class_(), 1));
  LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *elemCopy = (LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *) cast_chk([((LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *) nil_chk(elem)) java_clone], [LibOrgBouncycastlePqcMathLinearalgebraGF2nElement class]);
  if ([elemCopy isKindOfClass:[LibOrgBouncycastlePqcMathLinearalgebraGF2nONBElement class]]) {
    [((LibOrgBouncycastlePqcMathLinearalgebraGF2nONBElement *) nil_chk(((LibOrgBouncycastlePqcMathLinearalgebraGF2nONBElement *) elemCopy))) reverseOrder];
  }
  LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *bs = new_LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_initWithInt_withJavaMathBigInteger_(mDegree_, [((LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *) nil_chk(elemCopy)) toFlexiBigInt]);
  [bs expandNWithInt:mDegree_];
  LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *result = new_LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_initWithInt_(mDegree_);
  for (i = 0; i < mDegree_; i++) {
    if ([bs vectorMultWithLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial:IOSObjectArray_Get(nil_chk(COBMatrix), i)]) {
      [result setBitWithInt:mDegree_ - 1 - i];
    }
  }
  if ([basis isKindOfClass:[LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField class]]) {
    return new_LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialElement_initWithLibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField_withLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_((LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField *) basis, result);
  }
  else if ([basis isKindOfClass:[LibOrgBouncycastlePqcMathLinearalgebraGF2nONBField class]]) {
    LibOrgBouncycastlePqcMathLinearalgebraGF2nONBElement *res = new_LibOrgBouncycastlePqcMathLinearalgebraGF2nONBElement_initWithLibOrgBouncycastlePqcMathLinearalgebraGF2nONBField_withJavaMathBigInteger_((LibOrgBouncycastlePqcMathLinearalgebraGF2nONBField *) basis, [result toFlexiBigInt]);
    [res reverseOrder];
    return res;
  }
  else {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"GF2nField.convert: B1 must be an instance of GF2nPolynomialField or GF2nONBField!");
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x11, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial;", 0x11, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x11, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathLinearalgebraGF2nElement;", 0x404, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x404, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x404, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial;", 0x14, 8, 9, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathLinearalgebraGF2nElement;", 0x11, 10, 11, 12, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecuritySecureRandom:);
  methods[1].selector = @selector(getDegree);
  methods[2].selector = @selector(getFieldPolynomial);
  methods[3].selector = @selector(isEqual:);
  methods[4].selector = @selector(hash);
  methods[5].selector = @selector(getRandomRootWithLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial:);
  methods[6].selector = @selector(computeCOBMatrixWithLibOrgBouncycastlePqcMathLinearalgebraGF2nField:);
  methods[7].selector = @selector(computeFieldPolynomial);
  methods[8].selector = @selector(invertMatrixWithLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2PolynomialArray:);
  methods[9].selector = @selector(convertWithLibOrgBouncycastlePqcMathLinearalgebraGF2nElement:withLibOrgBouncycastlePqcMathLinearalgebraGF2nField:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
    { "mDegree_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "fieldPolynomial_", "LLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "fields_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "matrices_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecuritySecureRandom;", "equals", "LNSObject;", "hashCode", "getRandomRoot", "LLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial;", "computeCOBMatrix", "LLibOrgBouncycastlePqcMathLinearalgebraGF2nField;", "invertMatrix", "[LLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial;", "convert", "LLibOrgBouncycastlePqcMathLinearalgebraGF2nElement;LLibOrgBouncycastlePqcMathLinearalgebraGF2nField;", "LJavaLangRuntimeException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcMathLinearalgebraGF2nField = { "GF2nField", "lib.org.bouncycastle.pqc.math.linearalgebra", ptrTable, methods, fields, 7, 0x401, 10, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcMathLinearalgebraGF2nField;
}

@end

void LibOrgBouncycastlePqcMathLinearalgebraGF2nField_initWithJavaSecuritySecureRandom_(LibOrgBouncycastlePqcMathLinearalgebraGF2nField *self, JavaSecuritySecureRandom *random) {
  NSObject_init(self);
  self->random_ = random;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcMathLinearalgebraGF2nField)
