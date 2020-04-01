//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/ntru/polynomial/BigDecimalPolynomial.java
//

#include "BigDecimalPolynomial.h"
#include "BigIntPolynomial.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/math/BigDecimal.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial ()

- (LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)poly2;

- (IOSObjectArray *)copyOfWithJavaMathBigDecimalArray:(IOSObjectArray *)a
                                              withInt:(jint)length OBJC_METHOD_FAMILY_NONE;

- (IOSObjectArray *)copyOfRangeWithJavaMathBigDecimalArray:(IOSObjectArray *)a
                                                   withInt:(jint)from
                                                   withInt:(jint)to OBJC_METHOD_FAMILY_NONE;

@end

inline JavaMathBigDecimal *LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_get_ZERO(void);
static JavaMathBigDecimal *LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_ZERO;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial, ZERO, JavaMathBigDecimal *)

inline JavaMathBigDecimal *LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_get_ONE_HALF(void);
static JavaMathBigDecimal *LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_ONE_HALF;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial, ONE_HALF, JavaMathBigDecimal *)

__attribute__((unused)) static LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *poly2);

__attribute__((unused)) static IOSObjectArray *LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_copyOfWithJavaMathBigDecimalArray_withInt_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, IOSObjectArray *a, jint length);

__attribute__((unused)) static IOSObjectArray *LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_copyOfRangeWithJavaMathBigDecimalArray_withInt_withInt_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, IOSObjectArray *a, jint from, jint to);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial)

@implementation LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial

- (instancetype)initWithInt:(jint)N {
  LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithInt_(self, N);
  return self;
}

- (instancetype)initWithJavaMathBigDecimalArray:(IOSObjectArray *)coeffs {
  LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(self, coeffs);
  return self;
}

- (instancetype)initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)p {
  LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(self, p);
  return self;
}

- (void)halve {
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(coeffs_))->size_; i++) {
    (void) IOSObjectArray_Set(coeffs_, i, [((JavaMathBigDecimal *) nil_chk(IOSObjectArray_Get(coeffs_, i))) multiplyWithJavaMathBigDecimal:LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_ONE_HALF]);
  }
}

- (LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)multWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)poly2 {
  return [self multWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(poly2)];
}

- (LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)multWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)poly2 {
  jint N = ((IOSObjectArray *) nil_chk(coeffs_))->size_;
  if (((LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *) nil_chk(poly2))->coeffs_->size_ != N) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Number of coefficients must be the same");
  }
  LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *c = LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_(self, poly2);
  if (((IOSObjectArray *) nil_chk(((LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *) nil_chk(c))->coeffs_))->size_ > N) {
    for (jint k = N; k < ((IOSObjectArray *) nil_chk(c->coeffs_))->size_; k++) {
      (void) IOSObjectArray_Set(c->coeffs_, k - N, [((JavaMathBigDecimal *) nil_chk(IOSObjectArray_Get(c->coeffs_, k - N))) addWithJavaMathBigDecimal:IOSObjectArray_Get(c->coeffs_, k)]);
    }
    c->coeffs_ = LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_copyOfWithJavaMathBigDecimalArray_withInt_(self, c->coeffs_, N);
  }
  return c;
}

- (LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)poly2 {
  return LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_(self, poly2);
}

- (void)addWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)b {
  if (((IOSObjectArray *) nil_chk(((LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *) nil_chk(b))->coeffs_))->size_ > coeffs_->size_) {
    jint N = coeffs_->size_;
    coeffs_ = LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_copyOfWithJavaMathBigDecimalArray_withInt_(self, coeffs_, b->coeffs_->size_);
    for (jint i = N; i < ((IOSObjectArray *) nil_chk(coeffs_))->size_; i++) {
      (void) IOSObjectArray_Set(coeffs_, i, LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_ZERO);
    }
  }
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(b->coeffs_))->size_; i++) {
    (void) IOSObjectArray_Set(coeffs_, i, [((JavaMathBigDecimal *) nil_chk(IOSObjectArray_Get(coeffs_, i))) addWithJavaMathBigDecimal:IOSObjectArray_Get(b->coeffs_, i)]);
  }
}

- (void)subWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)b {
  if (((IOSObjectArray *) nil_chk(((LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *) nil_chk(b))->coeffs_))->size_ > coeffs_->size_) {
    jint N = coeffs_->size_;
    coeffs_ = LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_copyOfWithJavaMathBigDecimalArray_withInt_(self, coeffs_, b->coeffs_->size_);
    for (jint i = N; i < ((IOSObjectArray *) nil_chk(coeffs_))->size_; i++) {
      (void) IOSObjectArray_Set(coeffs_, i, LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_ZERO);
    }
  }
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(b->coeffs_))->size_; i++) {
    (void) IOSObjectArray_Set(coeffs_, i, [((JavaMathBigDecimal *) nil_chk(IOSObjectArray_Get(coeffs_, i))) subtractWithJavaMathBigDecimal:IOSObjectArray_Get(b->coeffs_, i)]);
  }
}

- (LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)round {
  jint N = ((IOSObjectArray *) nil_chk(coeffs_))->size_;
  LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *p = new_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithInt_(N);
  for (jint i = 0; i < N; i++) {
    (void) IOSObjectArray_Set(nil_chk(p->coeffs_), i, [((JavaMathBigDecimal *) nil_chk([((JavaMathBigDecimal *) nil_chk(IOSObjectArray_Get(nil_chk(coeffs_), i))) setScaleWithInt:0 withInt:JavaMathBigDecimal_ROUND_HALF_EVEN])) toBigInteger]);
  }
  return p;
}

- (id)java_clone {
  return new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_([((IOSObjectArray *) nil_chk(coeffs_)) java_clone]);
}

- (IOSObjectArray *)copyOfWithJavaMathBigDecimalArray:(IOSObjectArray *)a
                                              withInt:(jint)length {
  return LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_copyOfWithJavaMathBigDecimalArray_withInt_(self, a, length);
}

- (IOSObjectArray *)copyOfRangeWithJavaMathBigDecimalArray:(IOSObjectArray *)a
                                                   withInt:(jint)from
                                                   withInt:(jint)to {
  return LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_copyOfRangeWithJavaMathBigDecimalArray_withInt_withInt_(self, a, from, to);
}

- (IOSObjectArray *)getCoeffs {
  IOSObjectArray *tmp = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(coeffs_))->size_ type:JavaMathBigDecimal_class_()];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(coeffs_, 0, tmp, 0, coeffs_->size_);
  return tmp;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial;", 0x1, 3, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial;", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial;", 0x2, 5, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 6, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 7, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, 8, -1, -1, -1, -1, -1 },
    { NULL, "[LJavaMathBigDecimal;", 0x2, 9, 10, -1, -1, -1, -1 },
    { NULL, "[LJavaMathBigDecimal;", 0x2, 11, 12, -1, -1, -1, -1 },
    { NULL, "[LJavaMathBigDecimal;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:);
  methods[1].selector = @selector(initWithJavaMathBigDecimalArray:);
  methods[2].selector = @selector(initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:);
  methods[3].selector = @selector(halve);
  methods[4].selector = @selector(multWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:);
  methods[5].selector = @selector(multWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:);
  methods[6].selector = @selector(multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:);
  methods[7].selector = @selector(addWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:);
  methods[8].selector = @selector(subWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:);
  methods[9].selector = @selector(round);
  methods[10].selector = @selector(java_clone);
  methods[11].selector = @selector(copyOfWithJavaMathBigDecimalArray:withInt:);
  methods[12].selector = @selector(copyOfRangeWithJavaMathBigDecimalArray:withInt:withInt:);
  methods[13].selector = @selector(getCoeffs);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ZERO", "LJavaMathBigDecimal;", .constantValue.asLong = 0, 0x1a, -1, 13, -1, -1 },
    { "ONE_HALF", "LJavaMathBigDecimal;", .constantValue.asLong = 0, 0x1a, -1, 14, -1, -1 },
    { "coeffs_", "[LJavaMathBigDecimal;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I", "[LJavaMathBigDecimal;", "LLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;", "mult", "LLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial;", "multRecursive", "add", "sub", "clone", "copyOf", "[LJavaMathBigDecimal;I", "copyOfRange", "[LJavaMathBigDecimal;II", &LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_ZERO, &LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_ONE_HALF };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial = { "BigDecimalPolynomial", "lib.org.bouncycastle.pqc.math.ntru.polynomial", ptrTable, methods, fields, 7, 0x1, 14, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial class]) {
    LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_ZERO = new_JavaMathBigDecimal_initWithNSString_(@"0");
    LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_ONE_HALF = new_JavaMathBigDecimal_initWithNSString_(@"0.5");
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial)
  }
}

@end

void LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithInt_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, jint N) {
  NSObject_init(self);
  self->coeffs_ = [IOSObjectArray newArrayWithLength:N type:JavaMathBigDecimal_class_()];
  for (jint i = 0; i < N; i++) {
    (void) IOSObjectArray_Set(self->coeffs_, i, LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_ZERO);
  }
}

LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithInt_(jint N) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial, initWithInt_, N)
}

LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *create_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithInt_(jint N) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial, initWithInt_, N)
}

void LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, IOSObjectArray *coeffs) {
  NSObject_init(self);
  self->coeffs_ = coeffs;
}

LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(IOSObjectArray *coeffs) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial, initWithJavaMathBigDecimalArray_, coeffs)
}

LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *create_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(IOSObjectArray *coeffs) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial, initWithJavaMathBigDecimalArray_, coeffs)
}

void LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *p) {
  NSObject_init(self);
  jint N = ((IOSObjectArray *) nil_chk(((LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(p))->coeffs_))->size_;
  self->coeffs_ = [IOSObjectArray newArrayWithLength:N type:JavaMathBigDecimal_class_()];
  for (jint i = 0; i < N; i++) {
    (void) IOSObjectArray_SetAndConsume(nil_chk(self->coeffs_), i, new_JavaMathBigDecimal_initWithJavaMathBigInteger_(IOSObjectArray_Get(nil_chk(p->coeffs_), i)));
  }
}

LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *p) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial, initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_, p)
}

LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *create_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *p) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial, initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_, p)
}

LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *poly2) {
  IOSObjectArray *a = self->coeffs_;
  IOSObjectArray *b = ((LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *) nil_chk(poly2))->coeffs_;
  jint n = ((IOSObjectArray *) nil_chk(poly2->coeffs_))->size_;
  if (n <= 1) {
    IOSObjectArray *c = [self->coeffs_ java_clone];
    for (jint i = 0; i < ((IOSObjectArray *) nil_chk(self->coeffs_))->size_; i++) {
      (void) IOSObjectArray_Set(nil_chk(c), i, [((JavaMathBigDecimal *) nil_chk(IOSObjectArray_Get(c, i))) multiplyWithJavaMathBigDecimal:IOSObjectArray_Get(poly2->coeffs_, 0)]);
    }
    return new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(c);
  }
  else {
    jint n1 = n / 2;
    LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *a1 = new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_copyOfWithJavaMathBigDecimalArray_withInt_(self, a, n1));
    LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *a2 = new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_copyOfRangeWithJavaMathBigDecimalArray_withInt_withInt_(self, a, n1, n));
    LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *b1 = new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_copyOfWithJavaMathBigDecimalArray_withInt_(self, b, n1));
    LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *b2 = new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_copyOfRangeWithJavaMathBigDecimalArray_withInt_withInt_(self, b, n1, n));
    LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *A = (LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *) cast_chk([a1 java_clone], [LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial class]);
    [((LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *) nil_chk(A)) addWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:a2];
    LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *B = (LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *) cast_chk([b1 java_clone], [LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial class]);
    [((LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *) nil_chk(B)) addWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:b2];
    LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *c1 = LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_(a1, b1);
    LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *c2 = LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_(a2, b2);
    LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *c3 = LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_(A, B);
    [((LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *) nil_chk(c3)) subWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:c1];
    [c3 subWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:c2];
    LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *c = new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithInt_(2 * n - 1);
    for (jint i = 0; i < ((IOSObjectArray *) nil_chk(((LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *) nil_chk(c1))->coeffs_))->size_; i++) {
      (void) IOSObjectArray_Set(c->coeffs_, i, IOSObjectArray_Get(c1->coeffs_, i));
    }
    for (jint i = 0; i < ((IOSObjectArray *) nil_chk(c3->coeffs_))->size_; i++) {
      (void) IOSObjectArray_Set(c->coeffs_, n1 + i, [((JavaMathBigDecimal *) nil_chk(IOSObjectArray_Get(c->coeffs_, n1 + i))) addWithJavaMathBigDecimal:IOSObjectArray_Get(c3->coeffs_, i)]);
    }
    for (jint i = 0; i < ((IOSObjectArray *) nil_chk(((LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *) nil_chk(c2))->coeffs_))->size_; i++) {
      (void) IOSObjectArray_Set(c->coeffs_, 2 * n1 + i, [((JavaMathBigDecimal *) nil_chk(IOSObjectArray_Get(c->coeffs_, 2 * n1 + i))) addWithJavaMathBigDecimal:IOSObjectArray_Get(c2->coeffs_, i)]);
    }
    return c;
  }
}

IOSObjectArray *LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_copyOfWithJavaMathBigDecimalArray_withInt_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, IOSObjectArray *a, jint length) {
  IOSObjectArray *tmp = [IOSObjectArray newArrayWithLength:length type:JavaMathBigDecimal_class_()];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(a, 0, tmp, 0, ((IOSObjectArray *) nil_chk(a))->size_ < length ? a->size_ : length);
  return tmp;
}

IOSObjectArray *LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_copyOfRangeWithJavaMathBigDecimalArray_withInt_withInt_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, IOSObjectArray *a, jint from, jint to) {
  jint newLength = to - from;
  IOSObjectArray *tmp = [IOSObjectArray newArrayWithLength:to - from type:JavaMathBigDecimal_class_()];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(a, from, tmp, 0, (((IOSObjectArray *) nil_chk(a))->size_ - from) < newLength ? (a->size_ - from) : newLength);
  return tmp;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial)