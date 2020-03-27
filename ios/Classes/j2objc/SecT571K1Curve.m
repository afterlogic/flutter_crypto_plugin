//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecT571K1Curve.java
//

#include "ECCurve.h"
#include "ECFieldElement.h"
#include "ECLookupTable.h"
#include "ECMultiplier.h"
#include "ECPoint.h"
#include "Hex.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Nat576.h"
#include "SecT571FieldElement.h"
#include "SecT571K1Curve.h"
#include "SecT571K1Point.h"
#include "WTauNafMultiplier.h"
#include "java/math/BigInteger.h"

inline jint LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_get_SecT571K1_DEFAULT_COORDS(void);
#define LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_SecT571K1_DEFAULT_COORDS 6
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve, SecT571K1_DEFAULT_COORDS, jint)

@interface LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1 : NSObject < LibOrgBouncycastleMathEcECLookupTable > {
 @public
  LibOrgBouncycastleMathEcCustomSecSecT571K1Curve *this$0_;
  jint val$len_;
  IOSLongArray *val$table_;
}

- (instancetype)initWithLibOrgBouncycastleMathEcCustomSecSecT571K1Curve:(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve *)outer$
                                                                withInt:(jint)capture$0
                                                          withLongArray:(IOSLongArray *)capture$1;

- (jint)getSize;

- (LibOrgBouncycastleMathEcECPoint *)lookupWithInt:(jint)index;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1)

__attribute__((unused)) static void LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT571K1Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1 *self, LibOrgBouncycastleMathEcCustomSecSecT571K1Curve *outer$, jint capture$0, IOSLongArray *capture$1);

__attribute__((unused)) static LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1 *new_LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT571K1Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve *outer$, jint capture$0, IOSLongArray *capture$1) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1 *create_LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT571K1Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve *outer$, jint capture$0, IOSLongArray *capture$1);

@implementation LibOrgBouncycastleMathEcCustomSecSecT571K1Curve

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleMathEcECCurve *)cloneCurve {
  return new_LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_init();
}

- (jboolean)supportsCoordinateSystemWithInt:(jint)coord {
  switch (coord) {
    case LibOrgBouncycastleMathEcECCurve_COORD_LAMBDA_PROJECTIVE:
    return true;
    default:
    return false;
  }
}

- (id<LibOrgBouncycastleMathEcECMultiplier>)createDefaultMultiplier {
  return new_LibOrgBouncycastleMathEcWTauNafMultiplier_init();
}

- (jint)getFieldSize {
  return 571;
}

- (LibOrgBouncycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return new_LibOrgBouncycastleMathEcCustomSecSecT571FieldElement_initWithJavaMathBigInteger_(x);
}

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                                                                  withBoolean:(jboolean)withCompression {
  return new_LibOrgBouncycastleMathEcCustomSecSecT571K1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(self, x, y, withCompression);
}

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                              withLibOrgBouncycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                                                  withBoolean:(jboolean)withCompression {
  return new_LibOrgBouncycastleMathEcCustomSecSecT571K1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(self, x, y, zs, withCompression);
}

- (LibOrgBouncycastleMathEcECPoint *)getInfinity {
  return infinity_;
}

- (jboolean)isKoblitz {
  return true;
}

- (jint)getM {
  return 571;
}

- (jboolean)isTrinomial {
  return false;
}

- (jint)getK1 {
  return 2;
}

- (jint)getK2 {
  return 5;
}

- (jint)getK3 {
  return 10;
}

- (id<LibOrgBouncycastleMathEcECLookupTable>)createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points
                                                                                                        withInt:(jint)off
                                                                                                        withInt:(jint)len {
  jint FE_LONGS = 9;
  IOSLongArray *table = [IOSLongArray newArrayWithLength:len * FE_LONGS * 2];
  {
    jint pos = 0;
    for (jint i = 0; i < len; ++i) {
      LibOrgBouncycastleMathEcECPoint *p = IOSObjectArray_Get(nil_chk(points), off + i);
      LibOrgBouncycastleMathRawNat576_copy64WithLongArray_withInt_withLongArray_withInt_(((LibOrgBouncycastleMathEcCustomSecSecT571FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecT571FieldElement *) cast_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk(p)) getRawXCoord], [LibOrgBouncycastleMathEcCustomSecSecT571FieldElement class]))))->x_, 0, table, pos);
      pos += FE_LONGS;
      LibOrgBouncycastleMathRawNat576_copy64WithLongArray_withInt_withLongArray_withInt_(((LibOrgBouncycastleMathEcCustomSecSecT571FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecT571FieldElement *) cast_chk([p getRawYCoord], [LibOrgBouncycastleMathEcCustomSecSecT571FieldElement class]))))->x_, 0, table, pos);
      pos += FE_LONGS;
    }
  }
  return new_LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT571K1Curve_withInt_withLongArray_(self, len, table);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECCurve;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECMultiplier;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x4, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x4, 4, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECLookupTable;", 0x1, 7, 8, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(cloneCurve);
  methods[2].selector = @selector(supportsCoordinateSystemWithInt:);
  methods[3].selector = @selector(createDefaultMultiplier);
  methods[4].selector = @selector(getFieldSize);
  methods[5].selector = @selector(fromBigIntegerWithJavaMathBigInteger:);
  methods[6].selector = @selector(createRawPointWithLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:withBoolean:);
  methods[7].selector = @selector(createRawPointWithLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElementArray:withBoolean:);
  methods[8].selector = @selector(getInfinity);
  methods[9].selector = @selector(isKoblitz);
  methods[10].selector = @selector(getM);
  methods[11].selector = @selector(isTrinomial);
  methods[12].selector = @selector(getK1);
  methods[13].selector = @selector(getK2);
  methods[14].selector = @selector(getK3);
  methods[15].selector = @selector(createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "SecT571K1_DEFAULT_COORDS", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_SecT571K1_DEFAULT_COORDS, 0x1a, -1, -1, -1, -1 },
    { "infinity_", "LLibOrgBouncycastleMathEcCustomSecSecT571K1Point;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "supportsCoordinateSystem", "I", "fromBigInteger", "LJavaMathBigInteger;", "createRawPoint", "LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;Z", "LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;[LLibOrgBouncycastleMathEcECFieldElement;Z", "createCacheSafeLookupTable", "[LLibOrgBouncycastleMathEcECPoint;II" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecT571K1Curve = { "SecT571K1Curve", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 16, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecT571K1Curve;
}

@end

void LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_init(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve *self) {
  LibOrgBouncycastleMathEcECCurve_AbstractF2m_initWithInt_withInt_withInt_withInt_(self, 571, 2, 5, 10);
  self->infinity_ = new_LibOrgBouncycastleMathEcCustomSecSecT571K1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(self, nil, nil);
  self->a_ = [self fromBigIntegerWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(0)];
  self->b_ = [self fromBigIntegerWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(1)];
  self->order_ = new_JavaMathBigInteger_initWithInt_withByteArray_(1, LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(@"020000000000000000000000000000000000000000000000000000000000000000000000131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001"));
  self->cofactor_ = JavaMathBigInteger_valueOfWithLong_(4);
  self->coord_ = LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_SecT571K1_DEFAULT_COORDS;
}

LibOrgBouncycastleMathEcCustomSecSecT571K1Curve *new_LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve, init)
}

LibOrgBouncycastleMathEcCustomSecSecT571K1Curve *create_LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve)

@implementation LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1

- (instancetype)initWithLibOrgBouncycastleMathEcCustomSecSecT571K1Curve:(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve *)outer$
                                                                withInt:(jint)capture$0
                                                          withLongArray:(IOSLongArray *)capture$1 {
  LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT571K1Curve_withInt_withLongArray_(self, outer$, capture$0, capture$1);
  return self;
}

- (jint)getSize {
  return val$len_;
}

- (LibOrgBouncycastleMathEcECPoint *)lookupWithInt:(jint)index {
  IOSLongArray *x = LibOrgBouncycastleMathRawNat576_create64();
  IOSLongArray *y = LibOrgBouncycastleMathRawNat576_create64();
  jint pos = 0;
  for (jint i = 0; i < val$len_; ++i) {
    jlong MASK = JreRShift32(((i ^ index) - 1), 31);
    for (jint j = 0; j < 9; ++j) {
      *IOSLongArray_GetRef(nil_chk(x), j) ^= IOSLongArray_Get(nil_chk(val$table_), pos + j) & MASK;
      *IOSLongArray_GetRef(nil_chk(y), j) ^= IOSLongArray_Get(val$table_, pos + 9 + j) & MASK;
    }
    pos += (9 * 2);
  }
  return [this$0_ createRawPointWithLibOrgBouncycastleMathEcECFieldElement:new_LibOrgBouncycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(x) withLibOrgBouncycastleMathEcECFieldElement:new_LibOrgBouncycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(y) withBoolean:false];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleMathEcCustomSecSecT571K1Curve:withInt:withLongArray:);
  methods[1].selector = @selector(getSize);
  methods[2].selector = @selector(lookupWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LLibOrgBouncycastleMathEcCustomSecSecT571K1Curve;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$len_", "I", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$table_", "[J", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "lookup", "I", "LLibOrgBouncycastleMathEcCustomSecSecT571K1Curve;", "createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:withInt:withInt:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1 = { "", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x8010, 3, 3, 2, -1, 3, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1;
}

@end

void LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT571K1Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1 *self, LibOrgBouncycastleMathEcCustomSecSecT571K1Curve *outer$, jint capture$0, IOSLongArray *capture$1) {
  self->this$0_ = outer$;
  self->val$len_ = capture$0;
  self->val$table_ = capture$1;
  NSObject_init(self);
}

LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1 *new_LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT571K1Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve *outer$, jint capture$0, IOSLongArray *capture$1) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1, initWithLibOrgBouncycastleMathEcCustomSecSecT571K1Curve_withInt_withLongArray_, outer$, capture$0, capture$1)
}

LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1 *create_LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT571K1Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve *outer$, jint capture$0, IOSLongArray *capture$1) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT571K1Curve_1, initWithLibOrgBouncycastleMathEcCustomSecSecT571K1Curve_withInt_withLongArray_, outer$, capture$0, capture$1)
}
