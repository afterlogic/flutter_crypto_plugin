//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/ntru/polynomial/Resultant.java
//

#include "BigIntPolynomial.h"
#include "J2ObjC_source.h"
#include "Resultant.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastlePqcMathNtruPolynomialResultant

- (instancetype)initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)rho
                                                         withJavaMathBigInteger:(JavaMathBigInteger *)res {
  LibOrgBouncycastlePqcMathNtruPolynomialResultant_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_withJavaMathBigInteger_(self, rho, res);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:withJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "rho_", "LLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;", .constantValue.asLong = 0, 0x1, -1, -1, -1, -1 },
    { "res_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;LJavaMathBigInteger;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcMathNtruPolynomialResultant = { "Resultant", "lib.org.bouncycastle.pqc.math.ntru.polynomial", ptrTable, methods, fields, 7, 0x1, 1, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcMathNtruPolynomialResultant;
}

@end

void LibOrgBouncycastlePqcMathNtruPolynomialResultant_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_withJavaMathBigInteger_(LibOrgBouncycastlePqcMathNtruPolynomialResultant *self, LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *rho, JavaMathBigInteger *res) {
  NSObject_init(self);
  self->rho_ = rho;
  self->res_ = res;
}

LibOrgBouncycastlePqcMathNtruPolynomialResultant *new_LibOrgBouncycastlePqcMathNtruPolynomialResultant_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_withJavaMathBigInteger_(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *rho, JavaMathBigInteger *res) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialResultant, initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_withJavaMathBigInteger_, rho, res)
}

LibOrgBouncycastlePqcMathNtruPolynomialResultant *create_LibOrgBouncycastlePqcMathNtruPolynomialResultant_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_withJavaMathBigInteger_(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *rho, JavaMathBigInteger *res) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialResultant, initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_withJavaMathBigInteger_, rho, res)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcMathNtruPolynomialResultant)