//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecT163FieldElement.java
//

#include "Arrays.h"
#include "ECFieldElement.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Nat192.h"
#include "SecT163Field.h"
#include "SecT163FieldElement.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleMathEcCustomSecSecT163FieldElement

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithJavaMathBigInteger_(self, x);
  return self;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLongArray:(IOSLongArray *)x {
  LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithLongArray_(self, x);
  return self;
}

- (jboolean)isOne {
  return LibOrgBouncycastleMathRawNat192_isOne64WithLongArray_(x_);
}

- (jboolean)isZero {
  return LibOrgBouncycastleMathRawNat192_isZero64WithLongArray_(x_);
}

- (jboolean)testBitZero {
  return (IOSLongArray_Get(nil_chk(x_), 0) & 1LL) != 0LL;
}

- (JavaMathBigInteger *)toBigInteger {
  return LibOrgBouncycastleMathRawNat192_toBigInteger64WithLongArray_(x_);
}

- (NSString *)getFieldName {
  return @"SecT163Field";
}

- (jint)getFieldSize {
  return 163;
}

- (LibOrgBouncycastleMathEcECFieldElement *)addWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b {
  IOSLongArray *z = LibOrgBouncycastleMathRawNat192_create64();
  LibOrgBouncycastleMathEcCustomSecSecT163Field_addWithLongArray_withLongArray_withLongArray_(x_, ((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) cast_chk(b, [LibOrgBouncycastleMathEcCustomSecSecT163FieldElement class]))))->x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithLongArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)addOne {
  IOSLongArray *z = LibOrgBouncycastleMathRawNat192_create64();
  LibOrgBouncycastleMathEcCustomSecSecT163Field_addOneWithLongArray_withLongArray_(x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithLongArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)subtractWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b {
  return [self addWithLibOrgBouncycastleMathEcECFieldElement:b];
}

- (LibOrgBouncycastleMathEcECFieldElement *)multiplyWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b {
  IOSLongArray *z = LibOrgBouncycastleMathRawNat192_create64();
  LibOrgBouncycastleMathEcCustomSecSecT163Field_multiplyWithLongArray_withLongArray_withLongArray_(x_, ((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) cast_chk(b, [LibOrgBouncycastleMathEcCustomSecSecT163FieldElement class]))))->x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithLongArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)multiplyMinusProductWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b
                                                                withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                                withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y {
  return [self multiplyPlusProductWithLibOrgBouncycastleMathEcECFieldElement:b withLibOrgBouncycastleMathEcECFieldElement:x withLibOrgBouncycastleMathEcECFieldElement:y];
}

- (LibOrgBouncycastleMathEcECFieldElement *)multiplyPlusProductWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b
                                                               withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                               withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y {
  IOSLongArray *ax = self->x_;
  IOSLongArray *bx = ((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) cast_chk(b, [LibOrgBouncycastleMathEcCustomSecSecT163FieldElement class]))))->x_;
  IOSLongArray *xx = ((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) cast_chk(x, [LibOrgBouncycastleMathEcCustomSecSecT163FieldElement class]))))->x_;
  IOSLongArray *yx = ((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) cast_chk(y, [LibOrgBouncycastleMathEcCustomSecSecT163FieldElement class]))))->x_;
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat192_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT163Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(ax, bx, tt);
  LibOrgBouncycastleMathEcCustomSecSecT163Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(xx, yx, tt);
  IOSLongArray *z = LibOrgBouncycastleMathRawNat192_create64();
  LibOrgBouncycastleMathEcCustomSecSecT163Field_reduceWithLongArray_withLongArray_(tt, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithLongArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)divideWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b {
  return [self multiplyWithLibOrgBouncycastleMathEcECFieldElement:[((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(b)) invert]];
}

- (LibOrgBouncycastleMathEcECFieldElement *)negate {
  return self;
}

- (LibOrgBouncycastleMathEcECFieldElement *)square {
  IOSLongArray *z = LibOrgBouncycastleMathRawNat192_create64();
  LibOrgBouncycastleMathEcCustomSecSecT163Field_squareWithLongArray_withLongArray_(x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithLongArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)squareMinusProductWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                              withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y {
  return [self squarePlusProductWithLibOrgBouncycastleMathEcECFieldElement:x withLibOrgBouncycastleMathEcECFieldElement:y];
}

- (LibOrgBouncycastleMathEcECFieldElement *)squarePlusProductWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                             withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y {
  IOSLongArray *ax = self->x_;
  IOSLongArray *xx = ((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) cast_chk(x, [LibOrgBouncycastleMathEcCustomSecSecT163FieldElement class]))))->x_;
  IOSLongArray *yx = ((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) cast_chk(y, [LibOrgBouncycastleMathEcCustomSecSecT163FieldElement class]))))->x_;
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat192_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT163Field_squareAddToExtWithLongArray_withLongArray_(ax, tt);
  LibOrgBouncycastleMathEcCustomSecSecT163Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(xx, yx, tt);
  IOSLongArray *z = LibOrgBouncycastleMathRawNat192_create64();
  LibOrgBouncycastleMathEcCustomSecSecT163Field_reduceWithLongArray_withLongArray_(tt, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithLongArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)squarePowWithInt:(jint)pow {
  if (pow < 1) {
    return self;
  }
  IOSLongArray *z = LibOrgBouncycastleMathRawNat192_create64();
  LibOrgBouncycastleMathEcCustomSecSecT163Field_squareNWithLongArray_withInt_withLongArray_(x_, pow, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithLongArray_(z);
}

- (jint)trace {
  return LibOrgBouncycastleMathEcCustomSecSecT163Field_traceWithLongArray_(x_);
}

- (LibOrgBouncycastleMathEcECFieldElement *)invert {
  IOSLongArray *z = LibOrgBouncycastleMathRawNat192_create64();
  LibOrgBouncycastleMathEcCustomSecSecT163Field_invertWithLongArray_withLongArray_(x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithLongArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)sqrt {
  IOSLongArray *z = LibOrgBouncycastleMathRawNat192_create64();
  LibOrgBouncycastleMathEcCustomSecSecT163Field_sqrtWithLongArray_withLongArray_(x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithLongArray_(z);
}

- (jint)getRepresentation {
  return LibOrgBouncycastleMathEcECFieldElement_F2m_PPB;
}

- (jint)getM {
  return 163;
}

- (jint)getK1 {
  return 3;
}

- (jint)getK2 {
  return 6;
}

- (jint)getK3 {
  return 7;
}

- (jboolean)isEqual:(id)other {
  if (other == self) {
    return true;
  }
  if (!([other isKindOfClass:[LibOrgBouncycastleMathEcCustomSecSecT163FieldElement class]])) {
    return false;
  }
  LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *o = (LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) cast_chk(other, [LibOrgBouncycastleMathEcCustomSecSecT163FieldElement class]);
  return LibOrgBouncycastleMathRawNat192_eq64WithLongArray_withLongArray_(x_, ((LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *) nil_chk(o))->x_);
}

- (NSUInteger)hash {
  return 163763 ^ LibOrgBouncycastleUtilArrays_hashCodeWithLongArray_withInt_withInt_(x_, 0, 3);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 4, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 5, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 8, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 9, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 10, 11, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 12, 11, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 13, 14, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 15, 16, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 17, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:);
  methods[1].selector = @selector(init);
  methods[2].selector = @selector(initWithLongArray:);
  methods[3].selector = @selector(isOne);
  methods[4].selector = @selector(isZero);
  methods[5].selector = @selector(testBitZero);
  methods[6].selector = @selector(toBigInteger);
  methods[7].selector = @selector(getFieldName);
  methods[8].selector = @selector(getFieldSize);
  methods[9].selector = @selector(addWithLibOrgBouncycastleMathEcECFieldElement:);
  methods[10].selector = @selector(addOne);
  methods[11].selector = @selector(subtractWithLibOrgBouncycastleMathEcECFieldElement:);
  methods[12].selector = @selector(multiplyWithLibOrgBouncycastleMathEcECFieldElement:);
  methods[13].selector = @selector(multiplyMinusProductWithLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:);
  methods[14].selector = @selector(multiplyPlusProductWithLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:);
  methods[15].selector = @selector(divideWithLibOrgBouncycastleMathEcECFieldElement:);
  methods[16].selector = @selector(negate);
  methods[17].selector = @selector(square);
  methods[18].selector = @selector(squareMinusProductWithLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:);
  methods[19].selector = @selector(squarePlusProductWithLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:);
  methods[20].selector = @selector(squarePowWithInt:);
  methods[21].selector = @selector(trace);
  methods[22].selector = @selector(invert);
  methods[23].selector = @selector(sqrt);
  methods[24].selector = @selector(getRepresentation);
  methods[25].selector = @selector(getM);
  methods[26].selector = @selector(getK1);
  methods[27].selector = @selector(getK2);
  methods[28].selector = @selector(getK3);
  methods[29].selector = @selector(isEqual:);
  methods[30].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "x_", "[J", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;", "[J", "add", "LLibOrgBouncycastleMathEcECFieldElement;", "subtract", "multiply", "multiplyMinusProduct", "LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;", "multiplyPlusProduct", "divide", "squareMinusProduct", "LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;", "squarePlusProduct", "squarePow", "I", "equals", "LNSObject;", "hashCode" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecT163FieldElement = { "SecT163FieldElement", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 31, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement;
}

@end

void LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithJavaMathBigInteger_(LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *self, JavaMathBigInteger *x) {
  LibOrgBouncycastleMathEcECFieldElement_AbstractF2m_init(self);
  if (x == nil || [x signum] < 0 || [x bitLength] > 163) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"x value invalid for SecT163FieldElement");
  }
  self->x_ = LibOrgBouncycastleMathEcCustomSecSecT163Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *new_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT163FieldElement, initWithJavaMathBigInteger_, x)
}

LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *create_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT163FieldElement, initWithJavaMathBigInteger_, x)
}

void LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_init(LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *self) {
  LibOrgBouncycastleMathEcECFieldElement_AbstractF2m_init(self);
  self->x_ = LibOrgBouncycastleMathRawNat192_create64();
}

LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *new_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT163FieldElement, init)
}

LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *create_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT163FieldElement, init)
}

void LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithLongArray_(LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *self, IOSLongArray *x) {
  LibOrgBouncycastleMathEcECFieldElement_AbstractF2m_init(self);
  self->x_ = x;
}

LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *new_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithLongArray_(IOSLongArray *x) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT163FieldElement, initWithLongArray_, x)
}

LibOrgBouncycastleMathEcCustomSecSecT163FieldElement *create_LibOrgBouncycastleMathEcCustomSecSecT163FieldElement_initWithLongArray_(IOSLongArray *x) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT163FieldElement, initWithLongArray_, x)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecT163FieldElement)
