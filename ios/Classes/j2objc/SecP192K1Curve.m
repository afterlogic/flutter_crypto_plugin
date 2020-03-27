//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecP192K1Curve.java
//

#include "ECConstants.h"
#include "ECCurve.h"
#include "ECFieldElement.h"
#include "ECLookupTable.h"
#include "ECPoint.h"
#include "Hex.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Nat192.h"
#include "SecP192K1Curve.h"
#include "SecP192K1FieldElement.h"
#include "SecP192K1Point.h"
#include "java/math/BigInteger.h"

inline jint LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_get_SecP192K1_DEFAULT_COORDS(void);
#define LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_SecP192K1_DEFAULT_COORDS 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve, SecP192K1_DEFAULT_COORDS, jint)

@interface LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1 : NSObject < LibOrgBouncycastleMathEcECLookupTable > {
 @public
  LibOrgBouncycastleMathEcCustomSecSecP192K1Curve *this$0_;
  jint val$len_;
  IOSIntArray *val$table_;
}

- (instancetype)initWithLibOrgBouncycastleMathEcCustomSecSecP192K1Curve:(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve *)outer$
                                                                withInt:(jint)capture$0
                                                           withIntArray:(IOSIntArray *)capture$1;

- (jint)getSize;

- (LibOrgBouncycastleMathEcECPoint *)lookupWithInt:(jint)index;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1)

__attribute__((unused)) static void LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecP192K1Curve_withInt_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1 *self, LibOrgBouncycastleMathEcCustomSecSecP192K1Curve *outer$, jint capture$0, IOSIntArray *capture$1);

__attribute__((unused)) static LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1 *new_LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecP192K1Curve_withInt_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve *outer$, jint capture$0, IOSIntArray *capture$1) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1 *create_LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecP192K1Curve_withInt_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve *outer$, jint capture$0, IOSIntArray *capture$1);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve)

JavaMathBigInteger *LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_q;

@implementation LibOrgBouncycastleMathEcCustomSecSecP192K1Curve

+ (JavaMathBigInteger *)q {
  return LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_q;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleMathEcECCurve *)cloneCurve {
  return new_LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_init();
}

- (jboolean)supportsCoordinateSystemWithInt:(jint)coord {
  switch (coord) {
    case LibOrgBouncycastleMathEcECCurve_COORD_JACOBIAN:
    return true;
    default:
    return false;
  }
}

- (JavaMathBigInteger *)getQ {
  return LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_q;
}

- (jint)getFieldSize {
  return [((JavaMathBigInteger *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_q)) bitLength];
}

- (LibOrgBouncycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return new_LibOrgBouncycastleMathEcCustomSecSecP192K1FieldElement_initWithJavaMathBigInteger_(x);
}

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                                                                  withBoolean:(jboolean)withCompression {
  return new_LibOrgBouncycastleMathEcCustomSecSecP192K1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(self, x, y, withCompression);
}

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                              withLibOrgBouncycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                                                  withBoolean:(jboolean)withCompression {
  return new_LibOrgBouncycastleMathEcCustomSecSecP192K1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(self, x, y, zs, withCompression);
}

- (LibOrgBouncycastleMathEcECPoint *)getInfinity {
  return infinity_;
}

- (id<LibOrgBouncycastleMathEcECLookupTable>)createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points
                                                                                                        withInt:(jint)off
                                                                                                        withInt:(jint)len {
  jint FE_INTS = 6;
  IOSIntArray *table = [IOSIntArray newArrayWithLength:len * FE_INTS * 2];
  {
    jint pos = 0;
    for (jint i = 0; i < len; ++i) {
      LibOrgBouncycastleMathEcECPoint *p = IOSObjectArray_Get(nil_chk(points), off + i);
      LibOrgBouncycastleMathRawNat192_copy__WithIntArray_withInt_withIntArray_withInt_(((LibOrgBouncycastleMathEcCustomSecSecP192K1FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecP192K1FieldElement *) cast_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk(p)) getRawXCoord], [LibOrgBouncycastleMathEcCustomSecSecP192K1FieldElement class]))))->x_, 0, table, pos);
      pos += FE_INTS;
      LibOrgBouncycastleMathRawNat192_copy__WithIntArray_withInt_withIntArray_withInt_(((LibOrgBouncycastleMathEcCustomSecSecP192K1FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecP192K1FieldElement *) cast_chk([p getRawYCoord], [LibOrgBouncycastleMathEcCustomSecSecP192K1FieldElement class]))))->x_, 0, table, pos);
      pos += FE_INTS;
    }
  }
  return new_LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecP192K1Curve_withInt_withIntArray_(self, len, table);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECCurve;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x4, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x4, 4, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECLookupTable;", 0x1, 7, 8, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(cloneCurve);
  methods[2].selector = @selector(supportsCoordinateSystemWithInt:);
  methods[3].selector = @selector(getQ);
  methods[4].selector = @selector(getFieldSize);
  methods[5].selector = @selector(fromBigIntegerWithJavaMathBigInteger:);
  methods[6].selector = @selector(createRawPointWithLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:withBoolean:);
  methods[7].selector = @selector(createRawPointWithLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElementArray:withBoolean:);
  methods[8].selector = @selector(getInfinity);
  methods[9].selector = @selector(createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "q", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x19, -1, 9, -1, -1 },
    { "SecP192K1_DEFAULT_COORDS", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_SecP192K1_DEFAULT_COORDS, 0x1a, -1, -1, -1, -1 },
    { "infinity_", "LLibOrgBouncycastleMathEcCustomSecSecP192K1Point;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "supportsCoordinateSystem", "I", "fromBigInteger", "LJavaMathBigInteger;", "createRawPoint", "LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;Z", "LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;[LLibOrgBouncycastleMathEcECFieldElement;Z", "createCacheSafeLookupTable", "[LLibOrgBouncycastleMathEcECPoint;II", &LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_q };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecP192K1Curve = { "SecP192K1Curve", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 10, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecP192K1Curve;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleMathEcCustomSecSecP192K1Curve class]) {
    LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_q = new_JavaMathBigInteger_initWithInt_withByteArray_(1, LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(@"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37"));
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve)
  }
}

@end

void LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_init(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve *self) {
  LibOrgBouncycastleMathEcECCurve_AbstractFp_initWithJavaMathBigInteger_(self, LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_q);
  self->infinity_ = new_LibOrgBouncycastleMathEcCustomSecSecP192K1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(self, nil, nil);
  self->a_ = [self fromBigIntegerWithJavaMathBigInteger:JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ZERO)];
  self->b_ = [self fromBigIntegerWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(3)];
  self->order_ = new_JavaMathBigInteger_initWithInt_withByteArray_(1, LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(@"FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D"));
  self->cofactor_ = JavaMathBigInteger_valueOfWithLong_(1);
  self->coord_ = LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_SecP192K1_DEFAULT_COORDS;
}

LibOrgBouncycastleMathEcCustomSecSecP192K1Curve *new_LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve, init)
}

LibOrgBouncycastleMathEcCustomSecSecP192K1Curve *create_LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve)

@implementation LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1

- (instancetype)initWithLibOrgBouncycastleMathEcCustomSecSecP192K1Curve:(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve *)outer$
                                                                withInt:(jint)capture$0
                                                           withIntArray:(IOSIntArray *)capture$1 {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecP192K1Curve_withInt_withIntArray_(self, outer$, capture$0, capture$1);
  return self;
}

- (jint)getSize {
  return val$len_;
}

- (LibOrgBouncycastleMathEcECPoint *)lookupWithInt:(jint)index {
  IOSIntArray *x = LibOrgBouncycastleMathRawNat192_create();
  IOSIntArray *y = LibOrgBouncycastleMathRawNat192_create();
  jint pos = 0;
  for (jint i = 0; i < val$len_; ++i) {
    jint MASK = JreRShift32(((i ^ index) - 1), 31);
    for (jint j = 0; j < 6; ++j) {
      *IOSIntArray_GetRef(nil_chk(x), j) ^= IOSIntArray_Get(nil_chk(val$table_), pos + j) & MASK;
      *IOSIntArray_GetRef(nil_chk(y), j) ^= IOSIntArray_Get(val$table_, pos + 6 + j) & MASK;
    }
    pos += (6 * 2);
  }
  return [this$0_ createRawPointWithLibOrgBouncycastleMathEcECFieldElement:new_LibOrgBouncycastleMathEcCustomSecSecP192K1FieldElement_initWithIntArray_(x) withLibOrgBouncycastleMathEcECFieldElement:new_LibOrgBouncycastleMathEcCustomSecSecP192K1FieldElement_initWithIntArray_(y) withBoolean:false];
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
  methods[0].selector = @selector(initWithLibOrgBouncycastleMathEcCustomSecSecP192K1Curve:withInt:withIntArray:);
  methods[1].selector = @selector(getSize);
  methods[2].selector = @selector(lookupWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LLibOrgBouncycastleMathEcCustomSecSecP192K1Curve;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$len_", "I", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$table_", "[I", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "lookup", "I", "LLibOrgBouncycastleMathEcCustomSecSecP192K1Curve;", "createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:withInt:withInt:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1 = { "", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x8010, 3, 3, 2, -1, 3, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1;
}

@end

void LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecP192K1Curve_withInt_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1 *self, LibOrgBouncycastleMathEcCustomSecSecP192K1Curve *outer$, jint capture$0, IOSIntArray *capture$1) {
  self->this$0_ = outer$;
  self->val$len_ = capture$0;
  self->val$table_ = capture$1;
  NSObject_init(self);
}

LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1 *new_LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecP192K1Curve_withInt_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve *outer$, jint capture$0, IOSIntArray *capture$1) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1, initWithLibOrgBouncycastleMathEcCustomSecSecP192K1Curve_withInt_withIntArray_, outer$, capture$0, capture$1)
}

LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1 *create_LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecP192K1Curve_withInt_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve *outer$, jint capture$0, IOSIntArray *capture$1) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecP192K1Curve_1, initWithLibOrgBouncycastleMathEcCustomSecSecP192K1Curve_withInt_withIntArray_, outer$, capture$0, capture$1)
}
