//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/field/FiniteFields.java
//

#include "FiniteField.h"
#include "FiniteFields.h"
#include "GF2Polynomial.h"
#include "GenericPolynomialExtensionField.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PolynomialExtensionField.h"
#include "PrimeField.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleMathFieldFiniteFields)

id<LibOrgBouncycastleMathFieldFiniteField> LibOrgBouncycastleMathFieldFiniteFields_GF_2;
id<LibOrgBouncycastleMathFieldFiniteField> LibOrgBouncycastleMathFieldFiniteFields_GF_3;

@implementation LibOrgBouncycastleMathFieldFiniteFields

+ (id<LibOrgBouncycastleMathFieldFiniteField>)GF_2 {
  return LibOrgBouncycastleMathFieldFiniteFields_GF_2;
}

+ (id<LibOrgBouncycastleMathFieldFiniteField>)GF_3 {
  return LibOrgBouncycastleMathFieldFiniteFields_GF_3;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathFieldFiniteFields_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (id<LibOrgBouncycastleMathFieldPolynomialExtensionField>)getBinaryExtensionFieldWithIntArray:(IOSIntArray *)exponents {
  return LibOrgBouncycastleMathFieldFiniteFields_getBinaryExtensionFieldWithIntArray_(exponents);
}

+ (id<LibOrgBouncycastleMathFieldFiniteField>)getPrimeFieldWithJavaMathBigInteger:(JavaMathBigInteger *)characteristic {
  return LibOrgBouncycastleMathFieldFiniteFields_getPrimeFieldWithJavaMathBigInteger_(characteristic);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathFieldPolynomialExtensionField;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathFieldFiniteField;", 0x9, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getBinaryExtensionFieldWithIntArray:);
  methods[2].selector = @selector(getPrimeFieldWithJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "GF_2", "LLibOrgBouncycastleMathFieldFiniteField;", .constantValue.asLong = 0, 0x18, -1, 4, -1, -1 },
    { "GF_3", "LLibOrgBouncycastleMathFieldFiniteField;", .constantValue.asLong = 0, 0x18, -1, 5, -1, -1 },
  };
  static const void *ptrTable[] = { "getBinaryExtensionField", "[I", "getPrimeField", "LJavaMathBigInteger;", &LibOrgBouncycastleMathFieldFiniteFields_GF_2, &LibOrgBouncycastleMathFieldFiniteFields_GF_3 };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathFieldFiniteFields = { "FiniteFields", "lib.org.bouncycastle.math.field", ptrTable, methods, fields, 7, 0x401, 3, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathFieldFiniteFields;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleMathFieldFiniteFields class]) {
    LibOrgBouncycastleMathFieldFiniteFields_GF_2 = new_LibOrgBouncycastleMathFieldPrimeField_initWithJavaMathBigInteger_(JavaMathBigInteger_valueOfWithLong_(2));
    LibOrgBouncycastleMathFieldFiniteFields_GF_3 = new_LibOrgBouncycastleMathFieldPrimeField_initWithJavaMathBigInteger_(JavaMathBigInteger_valueOfWithLong_(3));
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleMathFieldFiniteFields)
  }
}

@end

void LibOrgBouncycastleMathFieldFiniteFields_init(LibOrgBouncycastleMathFieldFiniteFields *self) {
  NSObject_init(self);
}

id<LibOrgBouncycastleMathFieldPolynomialExtensionField> LibOrgBouncycastleMathFieldFiniteFields_getBinaryExtensionFieldWithIntArray_(IOSIntArray *exponents) {
  LibOrgBouncycastleMathFieldFiniteFields_initialize();
  if (IOSIntArray_Get(nil_chk(exponents), 0) != 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Irreducible polynomials in GF(2) must have constant term");
  }
  for (jint i = 1; i < exponents->size_; ++i) {
    if (IOSIntArray_Get(exponents, i) <= IOSIntArray_Get(exponents, i - 1)) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Polynomial exponents must be montonically increasing");
    }
  }
  return new_LibOrgBouncycastleMathFieldGenericPolynomialExtensionField_initWithLibOrgBouncycastleMathFieldFiniteField_withLibOrgBouncycastleMathFieldPolynomial_(LibOrgBouncycastleMathFieldFiniteFields_GF_2, new_LibOrgBouncycastleMathFieldGF2Polynomial_initWithIntArray_(exponents));
}

id<LibOrgBouncycastleMathFieldFiniteField> LibOrgBouncycastleMathFieldFiniteFields_getPrimeFieldWithJavaMathBigInteger_(JavaMathBigInteger *characteristic) {
  LibOrgBouncycastleMathFieldFiniteFields_initialize();
  jint bitLength = [((JavaMathBigInteger *) nil_chk(characteristic)) bitLength];
  if ([characteristic signum] <= 0 || bitLength < 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'characteristic' must be >= 2");
  }
  if (bitLength < 3) {
    switch ([characteristic intValue]) {
      case 2:
      return LibOrgBouncycastleMathFieldFiniteFields_GF_2;
      case 3:
      return LibOrgBouncycastleMathFieldFiniteFields_GF_3;
    }
  }
  return new_LibOrgBouncycastleMathFieldPrimeField_initWithJavaMathBigInteger_(characteristic);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathFieldFiniteFields)