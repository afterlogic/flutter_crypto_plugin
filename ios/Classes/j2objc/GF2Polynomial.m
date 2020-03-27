//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/field/GF2Polynomial.java
//

#include "Arrays.h"
#include "GF2Polynomial.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"

@implementation LibOrgBouncycastleMathFieldGF2Polynomial

- (instancetype)initWithIntArray:(IOSIntArray *)exponents {
  LibOrgBouncycastleMathFieldGF2Polynomial_initWithIntArray_(self, exponents);
  return self;
}

- (jint)getDegree {
  return IOSIntArray_Get(exponents_, ((IOSIntArray *) nil_chk(exponents_))->size_ - 1);
}

- (IOSIntArray *)getExponentsPresent {
  return LibOrgBouncycastleUtilArrays_cloneWithIntArray_(exponents_);
}

- (jboolean)isEqual:(id)obj {
  if (self == obj) {
    return true;
  }
  if (!([obj isKindOfClass:[LibOrgBouncycastleMathFieldGF2Polynomial class]])) {
    return false;
  }
  LibOrgBouncycastleMathFieldGF2Polynomial *other = (LibOrgBouncycastleMathFieldGF2Polynomial *) cast_chk(obj, [LibOrgBouncycastleMathFieldGF2Polynomial class]);
  return LibOrgBouncycastleUtilArrays_areEqualWithIntArray_withIntArray_(exponents_, ((LibOrgBouncycastleMathFieldGF2Polynomial *) nil_chk(other))->exponents_);
}

- (NSUInteger)hash {
  return LibOrgBouncycastleUtilArrays_hashCodeWithIntArray_(exponents_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithIntArray:);
  methods[1].selector = @selector(getDegree);
  methods[2].selector = @selector(getExponentsPresent);
  methods[3].selector = @selector(isEqual:);
  methods[4].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "exponents_", "[I", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[I", "equals", "LNSObject;", "hashCode" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathFieldGF2Polynomial = { "GF2Polynomial", "lib.org.bouncycastle.math.field", ptrTable, methods, fields, 7, 0x0, 5, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathFieldGF2Polynomial;
}

@end

void LibOrgBouncycastleMathFieldGF2Polynomial_initWithIntArray_(LibOrgBouncycastleMathFieldGF2Polynomial *self, IOSIntArray *exponents) {
  NSObject_init(self);
  self->exponents_ = LibOrgBouncycastleUtilArrays_cloneWithIntArray_(exponents);
}

LibOrgBouncycastleMathFieldGF2Polynomial *new_LibOrgBouncycastleMathFieldGF2Polynomial_initWithIntArray_(IOSIntArray *exponents) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathFieldGF2Polynomial, initWithIntArray_, exponents)
}

LibOrgBouncycastleMathFieldGF2Polynomial *create_LibOrgBouncycastleMathFieldGF2Polynomial_initWithIntArray_(IOSIntArray *exponents) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathFieldGF2Polynomial, initWithIntArray_, exponents)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathFieldGF2Polynomial)
