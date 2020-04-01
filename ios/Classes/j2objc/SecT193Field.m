//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecT193Field.java
//

#include "IOSPrimitiveArray.h"
#include "Interleave.h"
#include "J2ObjC_source.h"
#include "Nat256.h"
#include "SecT193Field.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"

inline jlong LibOrgBouncycastleMathEcCustomSecSecT193Field_get_M01(void);
#define LibOrgBouncycastleMathEcCustomSecSecT193Field_M01 1LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecT193Field, M01, jlong)

inline jlong LibOrgBouncycastleMathEcCustomSecSecT193Field_get_M49(void);
#define LibOrgBouncycastleMathEcCustomSecSecT193Field_M49 562949953421311LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecT193Field, M49, jlong)

@implementation LibOrgBouncycastleMathEcCustomSecSecT193Field

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)addWithLongArray:(IOSLongArray *)x
           withLongArray:(IOSLongArray *)y
           withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_addWithLongArray_withLongArray_withLongArray_(x, y, z);
}

+ (void)addExtWithLongArray:(IOSLongArray *)xx
              withLongArray:(IOSLongArray *)yy
              withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_addExtWithLongArray_withLongArray_withLongArray_(xx, yy, zz);
}

+ (void)addOneWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_addOneWithLongArray_withLongArray_(x, z);
}

+ (IOSLongArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return LibOrgBouncycastleMathEcCustomSecSecT193Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

+ (void)invertWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_invertWithLongArray_withLongArray_(x, z);
}

+ (void)multiplyWithLongArray:(IOSLongArray *)x
                withLongArray:(IOSLongArray *)y
                withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_multiplyWithLongArray_withLongArray_withLongArray_(x, y, z);
}

+ (void)multiplyAddToExtWithLongArray:(IOSLongArray *)x
                        withLongArray:(IOSLongArray *)y
                        withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(x, y, zz);
}

+ (void)reduceWithLongArray:(IOSLongArray *)xx
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_reduceWithLongArray_withLongArray_(xx, z);
}

+ (void)reduce63WithLongArray:(IOSLongArray *)z
                      withInt:(jint)zOff {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_reduce63WithLongArray_withInt_(z, zOff);
}

+ (void)sqrtWithLongArray:(IOSLongArray *)x
            withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_sqrtWithLongArray_withLongArray_(x, z);
}

+ (void)squareWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_squareWithLongArray_withLongArray_(x, z);
}

+ (void)squareAddToExtWithLongArray:(IOSLongArray *)x
                      withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_squareAddToExtWithLongArray_withLongArray_(x, zz);
}

+ (void)squareNWithLongArray:(IOSLongArray *)x
                     withInt:(jint)n
               withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_squareNWithLongArray_withInt_withLongArray_(x, n, z);
}

+ (jint)traceWithLongArray:(IOSLongArray *)x {
  return LibOrgBouncycastleMathEcCustomSecSecT193Field_traceWithLongArray_(x);
}

+ (void)implCompactExtWithLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implCompactExtWithLongArray_(zz);
}

+ (void)implExpandWithLongArray:(IOSLongArray *)x
                  withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implExpandWithLongArray_withLongArray_(x, z);
}

+ (void)implMultiplyWithLongArray:(IOSLongArray *)x
                    withLongArray:(IOSLongArray *)y
                    withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implMultiplyWithLongArray_withLongArray_withLongArray_(x, y, zz);
}

+ (void)implMulwAccWithLong:(jlong)x
                   withLong:(jlong)y
              withLongArray:(IOSLongArray *)z
                    withInt:(jint)zOff {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implMulwAccWithLong_withLong_withLongArray_withInt_(x, y, z, zOff);
}

+ (void)implSquareWithLongArray:(IOSLongArray *)x
                  withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implSquareWithLongArray_withLongArray_(x, zz);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 2, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "[J", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 7, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 8, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 9, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 10, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 11, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 13, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 14, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 15, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 16, 17, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 18, 19, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 20, 19, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 21, 4, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 22, 1, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 23, 24, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 25, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(addWithLongArray:withLongArray:withLongArray:);
  methods[2].selector = @selector(addExtWithLongArray:withLongArray:withLongArray:);
  methods[3].selector = @selector(addOneWithLongArray:withLongArray:);
  methods[4].selector = @selector(fromBigIntegerWithJavaMathBigInteger:);
  methods[5].selector = @selector(invertWithLongArray:withLongArray:);
  methods[6].selector = @selector(multiplyWithLongArray:withLongArray:withLongArray:);
  methods[7].selector = @selector(multiplyAddToExtWithLongArray:withLongArray:withLongArray:);
  methods[8].selector = @selector(reduceWithLongArray:withLongArray:);
  methods[9].selector = @selector(reduce63WithLongArray:withInt:);
  methods[10].selector = @selector(sqrtWithLongArray:withLongArray:);
  methods[11].selector = @selector(squareWithLongArray:withLongArray:);
  methods[12].selector = @selector(squareAddToExtWithLongArray:withLongArray:);
  methods[13].selector = @selector(squareNWithLongArray:withInt:withLongArray:);
  methods[14].selector = @selector(traceWithLongArray:);
  methods[15].selector = @selector(implCompactExtWithLongArray:);
  methods[16].selector = @selector(implExpandWithLongArray:withLongArray:);
  methods[17].selector = @selector(implMultiplyWithLongArray:withLongArray:withLongArray:);
  methods[18].selector = @selector(implMulwAccWithLong:withLong:withLongArray:withInt:);
  methods[19].selector = @selector(implSquareWithLongArray:withLongArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "M01", "J", .constantValue.asLong = LibOrgBouncycastleMathEcCustomSecSecT193Field_M01, 0x1a, -1, -1, -1, -1 },
    { "M49", "J", .constantValue.asLong = LibOrgBouncycastleMathEcCustomSecSecT193Field_M49, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "add", "[J[J[J", "addExt", "addOne", "[J[J", "fromBigInteger", "LJavaMathBigInteger;", "invert", "multiply", "multiplyAddToExt", "reduce", "reduce63", "[JI", "sqrt", "square", "squareAddToExt", "squareN", "[JI[J", "trace", "[J", "implCompactExt", "implExpand", "implMultiply", "implMulwAcc", "JJ[JI", "implSquare" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecT193Field = { "SecT193Field", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 20, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecT193Field;
}

@end

void LibOrgBouncycastleMathEcCustomSecSecT193Field_init(LibOrgBouncycastleMathEcCustomSecSecT193Field *self) {
  NSObject_init(self);
}

LibOrgBouncycastleMathEcCustomSecSecT193Field *new_LibOrgBouncycastleMathEcCustomSecSecT193Field_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT193Field, init)
}

LibOrgBouncycastleMathEcCustomSecSecT193Field *create_LibOrgBouncycastleMathEcCustomSecSecT193Field_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT193Field, init)
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_addWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  *IOSLongArray_GetRef(nil_chk(z), 0) = IOSLongArray_Get(nil_chk(x), 0) ^ IOSLongArray_Get(nil_chk(y), 0);
  *IOSLongArray_GetRef(z, 1) = IOSLongArray_Get(x, 1) ^ IOSLongArray_Get(y, 1);
  *IOSLongArray_GetRef(z, 2) = IOSLongArray_Get(x, 2) ^ IOSLongArray_Get(y, 2);
  *IOSLongArray_GetRef(z, 3) = IOSLongArray_Get(x, 3) ^ IOSLongArray_Get(y, 3);
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_addExtWithLongArray_withLongArray_withLongArray_(IOSLongArray *xx, IOSLongArray *yy, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  *IOSLongArray_GetRef(nil_chk(zz), 0) = IOSLongArray_Get(nil_chk(xx), 0) ^ IOSLongArray_Get(nil_chk(yy), 0);
  *IOSLongArray_GetRef(zz, 1) = IOSLongArray_Get(xx, 1) ^ IOSLongArray_Get(yy, 1);
  *IOSLongArray_GetRef(zz, 2) = IOSLongArray_Get(xx, 2) ^ IOSLongArray_Get(yy, 2);
  *IOSLongArray_GetRef(zz, 3) = IOSLongArray_Get(xx, 3) ^ IOSLongArray_Get(yy, 3);
  *IOSLongArray_GetRef(zz, 4) = IOSLongArray_Get(xx, 4) ^ IOSLongArray_Get(yy, 4);
  *IOSLongArray_GetRef(zz, 5) = IOSLongArray_Get(xx, 5) ^ IOSLongArray_Get(yy, 5);
  *IOSLongArray_GetRef(zz, 6) = IOSLongArray_Get(xx, 6) ^ IOSLongArray_Get(yy, 6);
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_addOneWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  *IOSLongArray_GetRef(nil_chk(z), 0) = IOSLongArray_Get(nil_chk(x), 0) ^ 1LL;
  *IOSLongArray_GetRef(z, 1) = IOSLongArray_Get(x, 1);
  *IOSLongArray_GetRef(z, 2) = IOSLongArray_Get(x, 2);
  *IOSLongArray_GetRef(z, 3) = IOSLongArray_Get(x, 3);
}

IOSLongArray *LibOrgBouncycastleMathEcCustomSecSecT193Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  IOSLongArray *z = LibOrgBouncycastleMathRawNat256_fromBigInteger64WithJavaMathBigInteger_(x);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_reduce63WithLongArray_withInt_(z, 0);
  return z;
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_invertWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  if (LibOrgBouncycastleMathRawNat256_isZero64WithLongArray_(x)) {
    @throw new_JavaLangIllegalStateException_init();
  }
  IOSLongArray *t0 = LibOrgBouncycastleMathRawNat256_create64();
  IOSLongArray *t1 = LibOrgBouncycastleMathRawNat256_create64();
  LibOrgBouncycastleMathEcCustomSecSecT193Field_squareWithLongArray_withLongArray_(x, t0);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_squareNWithLongArray_withInt_withLongArray_(t0, 1, t1);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_squareNWithLongArray_withInt_withLongArray_(t1, 1, t1);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_squareNWithLongArray_withInt_withLongArray_(t0, 3, t1);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_squareNWithLongArray_withInt_withLongArray_(t0, 6, t1);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_squareNWithLongArray_withInt_withLongArray_(t0, 12, t1);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_squareNWithLongArray_withInt_withLongArray_(t0, 24, t1);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_squareNWithLongArray_withInt_withLongArray_(t0, 48, t1);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_squareNWithLongArray_withInt_withLongArray_(t0, 96, t1);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, z);
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_multiplyWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat256_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implMultiplyWithLongArray_withLongArray_withLongArray_(x, y, tt);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_reduceWithLongArray_withLongArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat256_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implMultiplyWithLongArray_withLongArray_withLongArray_(x, y, tt);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_addExtWithLongArray_withLongArray_withLongArray_(zz, tt, zz);
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_reduceWithLongArray_withLongArray_(IOSLongArray *xx, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(xx), 0);
  jlong x1 = IOSLongArray_Get(xx, 1);
  jlong x2 = IOSLongArray_Get(xx, 2);
  jlong x3 = IOSLongArray_Get(xx, 3);
  jlong x4 = IOSLongArray_Get(xx, 4);
  jlong x5 = IOSLongArray_Get(xx, 5);
  jlong x6 = IOSLongArray_Get(xx, 6);
  x2 ^= (JreLShift64(x6, 63));
  x3 ^= (JreURShift64(x6, 1)) ^ (JreLShift64(x6, 14));
  x4 ^= (JreURShift64(x6, 50));
  x1 ^= (JreLShift64(x5, 63));
  x2 ^= (JreURShift64(x5, 1)) ^ (JreLShift64(x5, 14));
  x3 ^= (JreURShift64(x5, 50));
  x0 ^= (JreLShift64(x4, 63));
  x1 ^= (JreURShift64(x4, 1)) ^ (JreLShift64(x4, 14));
  x2 ^= (JreURShift64(x4, 50));
  jlong t = JreURShift64(x3, 1);
  *IOSLongArray_GetRef(nil_chk(z), 0) = x0 ^ t ^ (JreLShift64(t, 15));
  *IOSLongArray_GetRef(z, 1) = x1 ^ (JreURShift64(t, 49));
  *IOSLongArray_GetRef(z, 2) = x2;
  *IOSLongArray_GetRef(z, 3) = x3 & LibOrgBouncycastleMathEcCustomSecSecT193Field_M01;
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_reduce63WithLongArray_withInt_(IOSLongArray *z, jint zOff) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  jlong z3 = IOSLongArray_Get(nil_chk(z), zOff + 3);
  jlong t = JreURShift64(z3, 1);
  *IOSLongArray_GetRef(z, zOff) ^= t ^ (JreLShift64(t, 15));
  *IOSLongArray_GetRef(z, zOff + 1) ^= (JreURShift64(t, 49));
  *IOSLongArray_GetRef(z, zOff + 3) = z3 & LibOrgBouncycastleMathEcCustomSecSecT193Field_M01;
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_sqrtWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  jlong u0;
  jlong u1;
  u0 = LibOrgBouncycastleMathRawInterleave_unshuffleWithLong_(IOSLongArray_Get(nil_chk(x), 0));
  u1 = LibOrgBouncycastleMathRawInterleave_unshuffleWithLong_(IOSLongArray_Get(x, 1));
  jlong e0 = (u0 & (jlong) 0x00000000FFFFFFFFLL) | (JreLShift64(u1, 32));
  jlong c0 = (JreURShift64(u0, 32)) | (u1 & (jlong) 0xFFFFFFFF00000000LL);
  u0 = LibOrgBouncycastleMathRawInterleave_unshuffleWithLong_(IOSLongArray_Get(x, 2));
  jlong e1 = (u0 & (jlong) 0x00000000FFFFFFFFLL) ^ (JreLShift64(IOSLongArray_Get(x, 3), 32));
  jlong c1 = (JreURShift64(u0, 32));
  *IOSLongArray_GetRef(nil_chk(z), 0) = e0 ^ (JreLShift64(c0, 8));
  *IOSLongArray_GetRef(z, 1) = e1 ^ (JreLShift64(c1, 8)) ^ (JreURShift64(c0, 56)) ^ (JreLShift64(c0, 33));
  *IOSLongArray_GetRef(z, 2) = (JreURShift64(c1, 56)) ^ (JreLShift64(c1, 33)) ^ (JreURShift64(c0, 31));
  *IOSLongArray_GetRef(z, 3) = (JreURShift64(c1, 31));
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_squareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat256_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implSquareWithLongArray_withLongArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_reduceWithLongArray_withLongArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_squareAddToExtWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat256_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implSquareWithLongArray_withLongArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_addExtWithLongArray_withLongArray_withLongArray_(zz, tt, zz);
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_squareNWithLongArray_withInt_withLongArray_(IOSLongArray *x, jint n, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat256_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implSquareWithLongArray_withLongArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_reduceWithLongArray_withLongArray_(tt, z);
  while (--n > 0) {
    LibOrgBouncycastleMathEcCustomSecSecT193Field_implSquareWithLongArray_withLongArray_(z, tt);
    LibOrgBouncycastleMathEcCustomSecSecT193Field_reduceWithLongArray_withLongArray_(tt, z);
  }
}

jint LibOrgBouncycastleMathEcCustomSecSecT193Field_traceWithLongArray_(IOSLongArray *x) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  return (jint) (IOSLongArray_Get(nil_chk(x), 0)) & 1;
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_implCompactExtWithLongArray_(IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  jlong z0 = IOSLongArray_Get(nil_chk(zz), 0);
  jlong z1 = IOSLongArray_Get(zz, 1);
  jlong z2 = IOSLongArray_Get(zz, 2);
  jlong z3 = IOSLongArray_Get(zz, 3);
  jlong z4 = IOSLongArray_Get(zz, 4);
  jlong z5 = IOSLongArray_Get(zz, 5);
  jlong z6 = IOSLongArray_Get(zz, 6);
  jlong z7 = IOSLongArray_Get(zz, 7);
  *IOSLongArray_GetRef(zz, 0) = z0 ^ (JreLShift64(z1, 49));
  *IOSLongArray_GetRef(zz, 1) = (JreURShift64(z1, 15)) ^ (JreLShift64(z2, 34));
  *IOSLongArray_GetRef(zz, 2) = (JreURShift64(z2, 30)) ^ (JreLShift64(z3, 19));
  *IOSLongArray_GetRef(zz, 3) = (JreURShift64(z3, 45)) ^ (JreLShift64(z4, 4)) ^ (JreLShift64(z5, 53));
  *IOSLongArray_GetRef(zz, 4) = (JreURShift64(z4, 60)) ^ (JreLShift64(z6, 38)) ^ (JreURShift64(z5, 11));
  *IOSLongArray_GetRef(zz, 5) = (JreURShift64(z6, 26)) ^ (JreLShift64(z7, 23));
  *IOSLongArray_GetRef(zz, 6) = (JreURShift64(z7, 41));
  *IOSLongArray_GetRef(zz, 7) = 0;
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_implExpandWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(x), 0);
  jlong x1 = IOSLongArray_Get(x, 1);
  jlong x2 = IOSLongArray_Get(x, 2);
  jlong x3 = IOSLongArray_Get(x, 3);
  *IOSLongArray_GetRef(nil_chk(z), 0) = x0 & LibOrgBouncycastleMathEcCustomSecSecT193Field_M49;
  *IOSLongArray_GetRef(z, 1) = ((JreURShift64(x0, 49)) ^ (JreLShift64(x1, 15))) & LibOrgBouncycastleMathEcCustomSecSecT193Field_M49;
  *IOSLongArray_GetRef(z, 2) = ((JreURShift64(x1, 34)) ^ (JreLShift64(x2, 30))) & LibOrgBouncycastleMathEcCustomSecSecT193Field_M49;
  *IOSLongArray_GetRef(z, 3) = ((JreURShift64(x2, 19)) ^ (JreLShift64(x3, 45)));
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_implMultiplyWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  IOSLongArray *f = [IOSLongArray newArrayWithLength:4];
  IOSLongArray *g = [IOSLongArray newArrayWithLength:4];
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implExpandWithLongArray_withLongArray_(x, f);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implExpandWithLongArray_withLongArray_(y, g);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implMulwAccWithLong_withLong_withLongArray_withInt_(IOSLongArray_Get(f, 0), IOSLongArray_Get(g, 0), zz, 0);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implMulwAccWithLong_withLong_withLongArray_withInt_(IOSLongArray_Get(f, 1), IOSLongArray_Get(g, 1), zz, 1);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implMulwAccWithLong_withLong_withLongArray_withInt_(IOSLongArray_Get(f, 2), IOSLongArray_Get(g, 2), zz, 2);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implMulwAccWithLong_withLong_withLongArray_withInt_(IOSLongArray_Get(f, 3), IOSLongArray_Get(g, 3), zz, 3);
  for (jint i = 5; i > 0; --i) {
    *IOSLongArray_GetRef(nil_chk(zz), i) ^= IOSLongArray_Get(zz, i - 1);
  }
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implMulwAccWithLong_withLong_withLongArray_withInt_(IOSLongArray_Get(f, 0) ^ IOSLongArray_Get(f, 1), IOSLongArray_Get(g, 0) ^ IOSLongArray_Get(g, 1), zz, 1);
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implMulwAccWithLong_withLong_withLongArray_withInt_(IOSLongArray_Get(f, 2) ^ IOSLongArray_Get(f, 3), IOSLongArray_Get(g, 2) ^ IOSLongArray_Get(g, 3), zz, 3);
  for (jint i = 7; i > 1; --i) {
    *IOSLongArray_GetRef(nil_chk(zz), i) ^= IOSLongArray_Get(zz, i - 2);
  }
  {
    jlong c0 = IOSLongArray_Get(f, 0) ^ IOSLongArray_Get(f, 2);
    jlong c1 = IOSLongArray_Get(f, 1) ^ IOSLongArray_Get(f, 3);
    jlong d0 = IOSLongArray_Get(g, 0) ^ IOSLongArray_Get(g, 2);
    jlong d1 = IOSLongArray_Get(g, 1) ^ IOSLongArray_Get(g, 3);
    LibOrgBouncycastleMathEcCustomSecSecT193Field_implMulwAccWithLong_withLong_withLongArray_withInt_(c0 ^ c1, d0 ^ d1, zz, 3);
    IOSLongArray *t = [IOSLongArray newArrayWithLength:3];
    LibOrgBouncycastleMathEcCustomSecSecT193Field_implMulwAccWithLong_withLong_withLongArray_withInt_(c0, d0, t, 0);
    LibOrgBouncycastleMathEcCustomSecSecT193Field_implMulwAccWithLong_withLong_withLongArray_withInt_(c1, d1, t, 1);
    jlong t0 = IOSLongArray_Get(t, 0);
    jlong t1 = IOSLongArray_Get(t, 1);
    jlong t2 = IOSLongArray_Get(t, 2);
    *IOSLongArray_GetRef(nil_chk(zz), 2) ^= t0;
    *IOSLongArray_GetRef(zz, 3) ^= t0 ^ t1;
    *IOSLongArray_GetRef(zz, 4) ^= t2 ^ t1;
    *IOSLongArray_GetRef(zz, 5) ^= t2;
  }
  LibOrgBouncycastleMathEcCustomSecSecT193Field_implCompactExtWithLongArray_(zz);
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_implMulwAccWithLong_withLong_withLongArray_withInt_(jlong x, jlong y, IOSLongArray *z, jint zOff) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  IOSLongArray *u = [IOSLongArray newArrayWithLength:8];
  *IOSLongArray_GetRef(u, 1) = y;
  *IOSLongArray_GetRef(u, 2) = JreLShift64(IOSLongArray_Get(u, 1), 1);
  *IOSLongArray_GetRef(u, 3) = IOSLongArray_Get(u, 2) ^ y;
  *IOSLongArray_GetRef(u, 4) = JreLShift64(IOSLongArray_Get(u, 2), 1);
  *IOSLongArray_GetRef(u, 5) = IOSLongArray_Get(u, 4) ^ y;
  *IOSLongArray_GetRef(u, 6) = JreLShift64(IOSLongArray_Get(u, 3), 1);
  *IOSLongArray_GetRef(u, 7) = IOSLongArray_Get(u, 6) ^ y;
  jint j = (jint) x;
  jlong g;
  jlong h = 0;
  jlong l = IOSLongArray_Get(u, j & 7) ^ (JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 3)) & 7), 3));
  jint k = 36;
  do {
    j = (jint) (JreURShift64(x, k));
    g = IOSLongArray_Get(u, j & 7) ^ JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 3)) & 7), 3) ^ JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 6)) & 7), 6) ^ JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 9)) & 7), 9) ^ JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 12)) & 7), 12);
    l ^= (JreLShift64(g, k));
    h ^= (JreURShift64(g, -k));
  }
  while ((k -= 15) > 0);
  *IOSLongArray_GetRef(nil_chk(z), zOff) ^= l & LibOrgBouncycastleMathEcCustomSecSecT193Field_M49;
  *IOSLongArray_GetRef(z, zOff + 1) ^= (JreURShift64(l, 49)) ^ (JreLShift64(h, 15));
}

void LibOrgBouncycastleMathEcCustomSecSecT193Field_implSquareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT193Field_initialize();
  LibOrgBouncycastleMathRawInterleave_expand64To128WithLong_withLongArray_withInt_(IOSLongArray_Get(nil_chk(x), 0), zz, 0);
  LibOrgBouncycastleMathRawInterleave_expand64To128WithLong_withLongArray_withInt_(IOSLongArray_Get(x, 1), zz, 2);
  LibOrgBouncycastleMathRawInterleave_expand64To128WithLong_withLongArray_withInt_(IOSLongArray_Get(x, 2), zz, 4);
  *IOSLongArray_GetRef(nil_chk(zz), 6) = (IOSLongArray_Get(x, 3) & LibOrgBouncycastleMathEcCustomSecSecT193Field_M01);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecT193Field)