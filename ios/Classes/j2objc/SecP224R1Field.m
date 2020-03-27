//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecP224R1Field.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Nat.h"
#include "Nat224.h"
#include "SecP224R1Field.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleMathEcCustomSecSecP224R1Field ()

+ (void)addPInvToWithIntArray:(IOSIntArray *)z;

+ (void)subPInvFromWithIntArray:(IOSIntArray *)z;

@end

inline jlong LibOrgBouncycastleMathEcCustomSecSecP224R1Field_get_M(void);
#define LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M 4294967295LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP224R1Field, M, jlong)

inline IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP224R1Field_get_PExtInv(void);
static IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExtInv;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleMathEcCustomSecSecP224R1Field, PExtInv, IOSIntArray *)

inline jint LibOrgBouncycastleMathEcCustomSecSecP224R1Field_get_P6(void);
#define LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P6 -1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP224R1Field, P6, jint)

inline jint LibOrgBouncycastleMathEcCustomSecSecP224R1Field_get_PExt13(void);
#define LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExt13 -1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP224R1Field, PExt13, jint)

__attribute__((unused)) static void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addPInvToWithIntArray_(IOSIntArray *z);

__attribute__((unused)) static void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_subPInvFromWithIntArray_(IOSIntArray *z);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleMathEcCustomSecSecP224R1Field)

IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P;
IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExt;

@implementation LibOrgBouncycastleMathEcCustomSecSecP224R1Field

+ (IOSIntArray *)P {
  return LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P;
}

+ (IOSIntArray *)PExt {
  return LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExt;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)addWithIntArray:(IOSIntArray *)x
           withIntArray:(IOSIntArray *)y
           withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)addExtWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)yy
              withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)addOneWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addOneWithIntArray_withIntArray_(x, z);
}

+ (IOSIntArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return LibOrgBouncycastleMathEcCustomSecSecP224R1Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

+ (void)halfWithIntArray:(IOSIntArray *)x
            withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_halfWithIntArray_withIntArray_(x, z);
}

+ (void)multiplyWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_multiplyWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)multiplyAddToExtWithIntArray:(IOSIntArray *)x
                        withIntArray:(IOSIntArray *)y
                        withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(x, y, zz);
}

+ (void)negateWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_negateWithIntArray_withIntArray_(x, z);
}

+ (void)reduceWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_reduceWithIntArray_withIntArray_(xx, z);
}

+ (void)reduce32WithInt:(jint)x
           withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_reduce32WithInt_withIntArray_(x, z);
}

+ (void)squareWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_squareWithIntArray_withIntArray_(x, z);
}

+ (void)squareNWithIntArray:(IOSIntArray *)x
                    withInt:(jint)n
               withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_squareNWithIntArray_withInt_withIntArray_(x, n, z);
}

+ (void)subtractWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_subtractWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)subtractExtWithIntArray:(IOSIntArray *)xx
                   withIntArray:(IOSIntArray *)yy
                   withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_subtractExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)twiceWithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_twiceWithIntArray_withIntArray_(x, z);
}

+ (void)addPInvToWithIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addPInvToWithIntArray_(z);
}

+ (void)subPInvFromWithIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_subPInvFromWithIntArray_(z);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 2, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "[I", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 7, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 8, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 9, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 10, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 11, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 12, 13, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 14, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 15, 16, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 17, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 18, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 19, 4, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 20, 21, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 22, 21, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(addWithIntArray:withIntArray:withIntArray:);
  methods[2].selector = @selector(addExtWithIntArray:withIntArray:withIntArray:);
  methods[3].selector = @selector(addOneWithIntArray:withIntArray:);
  methods[4].selector = @selector(fromBigIntegerWithJavaMathBigInteger:);
  methods[5].selector = @selector(halfWithIntArray:withIntArray:);
  methods[6].selector = @selector(multiplyWithIntArray:withIntArray:withIntArray:);
  methods[7].selector = @selector(multiplyAddToExtWithIntArray:withIntArray:withIntArray:);
  methods[8].selector = @selector(negateWithIntArray:withIntArray:);
  methods[9].selector = @selector(reduceWithIntArray:withIntArray:);
  methods[10].selector = @selector(reduce32WithInt:withIntArray:);
  methods[11].selector = @selector(squareWithIntArray:withIntArray:);
  methods[12].selector = @selector(squareNWithIntArray:withInt:withIntArray:);
  methods[13].selector = @selector(subtractWithIntArray:withIntArray:withIntArray:);
  methods[14].selector = @selector(subtractExtWithIntArray:withIntArray:withIntArray:);
  methods[15].selector = @selector(twiceWithIntArray:withIntArray:);
  methods[16].selector = @selector(addPInvToWithIntArray:);
  methods[17].selector = @selector(subPInvFromWithIntArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "M", "J", .constantValue.asLong = LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M, 0x1a, -1, -1, -1, -1 },
    { "P", "[I", .constantValue.asLong = 0, 0x18, -1, 23, -1, -1 },
    { "PExt", "[I", .constantValue.asLong = 0, 0x18, -1, 24, -1, -1 },
    { "PExtInv", "[I", .constantValue.asLong = 0, 0x1a, -1, 25, -1, -1 },
    { "P6", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P6, 0x1a, -1, -1, -1, -1 },
    { "PExt13", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExt13, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "add", "[I[I[I", "addExt", "addOne", "[I[I", "fromBigInteger", "LJavaMathBigInteger;", "half", "multiply", "multiplyAddToExt", "negate", "reduce", "reduce32", "I[I", "square", "squareN", "[II[I", "subtract", "subtractExt", "twice", "addPInvTo", "[I", "subPInvFrom", &LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P, &LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExt, &LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExtInv };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecP224R1Field = { "SecP224R1Field", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 18, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecP224R1Field;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleMathEcCustomSecSecP224R1Field class]) {
    LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0x00000001, (jint) 0x00000000, (jint) 0x00000000, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF } count:7];
    LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExt = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0x00000001, (jint) 0x00000000, (jint) 0x00000000, (jint) 0xFFFFFFFE, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0x00000000, (jint) 0x00000002, (jint) 0x00000000, (jint) 0x00000000, (jint) 0xFFFFFFFE, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF } count:14];
    LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExtInv = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0x00000001, (jint) 0x00000000, (jint) 0x00000000, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFD, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0x00000001 } count:11];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleMathEcCustomSecSecP224R1Field)
  }
}

@end

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_init(LibOrgBouncycastleMathEcCustomSecSecP224R1Field *self) {
  NSObject_init(self);
}

LibOrgBouncycastleMathEcCustomSecSecP224R1Field *new_LibOrgBouncycastleMathEcCustomSecSecP224R1Field_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecP224R1Field, init)
}

LibOrgBouncycastleMathEcCustomSecSecP224R1Field *create_LibOrgBouncycastleMathEcCustomSecSecP224R1Field_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecP224R1Field, init)
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat224_addWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 6) == LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P6 && LibOrgBouncycastleMathRawNat224_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P))) {
    LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addPInvToWithIntArray_(z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_addWithInt_withIntArray_withIntArray_withIntArray_(14, xx, yy, zz);
  if (c != 0 || (IOSIntArray_Get(nil_chk(zz), 13) == LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExt13 && LibOrgBouncycastleMathRawNat_gteWithInt_withIntArray_withIntArray_(14, zz, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExt))) {
    if (LibOrgBouncycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExtInv, zz) != 0) {
      LibOrgBouncycastleMathRawNat_incAtWithInt_withIntArray_withInt_(14, zz, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExtInv->size_);
    }
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addOneWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_incWithInt_withIntArray_withIntArray_(7, x, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 6) == LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P6 && LibOrgBouncycastleMathRawNat224_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P))) {
    LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addPInvToWithIntArray_(z);
  }
}

IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP224R1Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  IOSIntArray *z = LibOrgBouncycastleMathRawNat224_fromBigIntegerWithJavaMathBigInteger_(x);
  if (IOSIntArray_Get(nil_chk(z), 6) == LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P6 && LibOrgBouncycastleMathRawNat224_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P)) {
    LibOrgBouncycastleMathRawNat224_subFromWithIntArray_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P, z);
  }
  return z;
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_halfWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  if ((IOSIntArray_Get(nil_chk(x), 0) & 1) == 0) {
    LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_withIntArray_(7, x, 0, z);
  }
  else {
    jint c = LibOrgBouncycastleMathRawNat224_addWithIntArray_withIntArray_withIntArray_(x, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P, z);
    LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_(7, z, c);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_multiplyWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat224_createExt();
  LibOrgBouncycastleMathRawNat224_mulWithIntArray_withIntArray_withIntArray_(x, y, tt);
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat224_mulAddToWithIntArray_withIntArray_withIntArray_(x, y, zz);
  if (c != 0 || (IOSIntArray_Get(nil_chk(zz), 13) == LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExt13 && LibOrgBouncycastleMathRawNat_gteWithInt_withIntArray_withIntArray_(14, zz, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExt))) {
    if (LibOrgBouncycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExtInv, zz) != 0) {
      LibOrgBouncycastleMathRawNat_incAtWithInt_withIntArray_withInt_(14, zz, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExtInv->size_);
    }
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_negateWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  if (LibOrgBouncycastleMathRawNat224_isZeroWithIntArray_(x)) {
    LibOrgBouncycastleMathRawNat224_zeroWithIntArray_(z);
  }
  else {
    LibOrgBouncycastleMathRawNat224_subWithIntArray_withIntArray_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P, x, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_reduceWithIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  jlong xx10 = IOSIntArray_Get(nil_chk(xx), 10) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M;
  jlong xx11 = IOSIntArray_Get(xx, 11) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M;
  jlong xx12 = IOSIntArray_Get(xx, 12) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M;
  jlong xx13 = IOSIntArray_Get(xx, 13) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M;
  jlong n = 1;
  jlong t0 = (IOSIntArray_Get(xx, 7) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) + xx11 - n;
  jlong t1 = (IOSIntArray_Get(xx, 8) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) + xx12;
  jlong t2 = (IOSIntArray_Get(xx, 9) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) + xx13;
  jlong cc = 0;
  cc += (IOSIntArray_Get(xx, 0) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) - t0;
  jlong z0 = cc & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M;
  JreRShiftAssignLong(&cc, 32);
  cc += (IOSIntArray_Get(xx, 1) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) - t1;
  *IOSIntArray_GetRef(nil_chk(z), 1) = (jint) cc;
  JreRShiftAssignLong(&cc, 32);
  cc += (IOSIntArray_Get(xx, 2) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) - t2;
  *IOSIntArray_GetRef(z, 2) = (jint) cc;
  JreRShiftAssignLong(&cc, 32);
  cc += (IOSIntArray_Get(xx, 3) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) + t0 - xx10;
  jlong z3 = cc & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M;
  JreRShiftAssignLong(&cc, 32);
  cc += (IOSIntArray_Get(xx, 4) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) + t1 - xx11;
  *IOSIntArray_GetRef(z, 4) = (jint) cc;
  JreRShiftAssignLong(&cc, 32);
  cc += (IOSIntArray_Get(xx, 5) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) + t2 - xx12;
  *IOSIntArray_GetRef(z, 5) = (jint) cc;
  JreRShiftAssignLong(&cc, 32);
  cc += (IOSIntArray_Get(xx, 6) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) + xx10 - xx13;
  *IOSIntArray_GetRef(z, 6) = (jint) cc;
  JreRShiftAssignLong(&cc, 32);
  cc += n;
  z3 += cc;
  z0 -= cc;
  *IOSIntArray_GetRef(z, 0) = (jint) z0;
  cc = JreRShift64(z0, 32);
  if (cc != 0) {
    cc += (IOSIntArray_Get(z, 1) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M);
    *IOSIntArray_GetRef(z, 1) = (jint) cc;
    JreRShiftAssignLong(&cc, 32);
    cc += (IOSIntArray_Get(z, 2) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M);
    *IOSIntArray_GetRef(z, 2) = (jint) cc;
    z3 += JreRShift64(cc, 32);
  }
  *IOSIntArray_GetRef(z, 3) = (jint) z3;
  cc = JreRShift64(z3, 32);
  if ((cc != 0 && LibOrgBouncycastleMathRawNat_incAtWithInt_withIntArray_withInt_(7, z, 4) != 0) || (IOSIntArray_Get(z, 6) == LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P6 && LibOrgBouncycastleMathRawNat224_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P))) {
    LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addPInvToWithIntArray_(z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_reduce32WithInt_withIntArray_(jint x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  jlong cc = 0;
  if (x != 0) {
    jlong xx07 = x & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M;
    cc += (IOSIntArray_Get(nil_chk(z), 0) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) - xx07;
    *IOSIntArray_GetRef(z, 0) = (jint) cc;
    JreRShiftAssignLong(&cc, 32);
    if (cc != 0) {
      cc += (IOSIntArray_Get(z, 1) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M);
      *IOSIntArray_GetRef(z, 1) = (jint) cc;
      JreRShiftAssignLong(&cc, 32);
      cc += (IOSIntArray_Get(z, 2) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M);
      *IOSIntArray_GetRef(z, 2) = (jint) cc;
      JreRShiftAssignLong(&cc, 32);
    }
    cc += (IOSIntArray_Get(z, 3) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) + xx07;
    *IOSIntArray_GetRef(z, 3) = (jint) cc;
    JreRShiftAssignLong(&cc, 32);
  }
  if ((cc != 0 && LibOrgBouncycastleMathRawNat_incAtWithInt_withIntArray_withInt_(7, z, 4) != 0) || (IOSIntArray_Get(nil_chk(z), 6) == LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P6 && LibOrgBouncycastleMathRawNat224_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P))) {
    LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addPInvToWithIntArray_(z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_squareWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat224_createExt();
  LibOrgBouncycastleMathRawNat224_squareWithIntArray_withIntArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_squareNWithIntArray_withInt_withIntArray_(IOSIntArray *x, jint n, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat224_createExt();
  LibOrgBouncycastleMathRawNat224_squareWithIntArray_withIntArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_reduceWithIntArray_withIntArray_(tt, z);
  while (--n > 0) {
    LibOrgBouncycastleMathRawNat224_squareWithIntArray_withIntArray_(z, tt);
    LibOrgBouncycastleMathEcCustomSecSecP224R1Field_reduceWithIntArray_withIntArray_(tt, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_subtractWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat224_subWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0) {
    LibOrgBouncycastleMathEcCustomSecSecP224R1Field_subPInvFromWithIntArray_(z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_subtractExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_subWithInt_withIntArray_withIntArray_withIntArray_(14, xx, yy, zz);
  if (c != 0) {
    if (LibOrgBouncycastleMathRawNat_subFromWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExtInv, zz) != 0) {
      LibOrgBouncycastleMathRawNat_decAtWithInt_withIntArray_withInt_(14, zz, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_PExtInv->size_);
    }
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_twiceWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_shiftUpBitWithInt_withIntArray_withInt_withIntArray_(7, x, 0, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 6) == LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P6 && LibOrgBouncycastleMathRawNat224_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP224R1Field_P))) {
    LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addPInvToWithIntArray_(z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_addPInvToWithIntArray_(IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  jlong c = (IOSIntArray_Get(nil_chk(z), 0) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) - 1;
  *IOSIntArray_GetRef(z, 0) = (jint) c;
  JreRShiftAssignLong(&c, 32);
  if (c != 0) {
    c += (IOSIntArray_Get(z, 1) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M);
    *IOSIntArray_GetRef(z, 1) = (jint) c;
    JreRShiftAssignLong(&c, 32);
    c += (IOSIntArray_Get(z, 2) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M);
    *IOSIntArray_GetRef(z, 2) = (jint) c;
    JreRShiftAssignLong(&c, 32);
  }
  c += (IOSIntArray_Get(z, 3) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) + 1;
  *IOSIntArray_GetRef(z, 3) = (jint) c;
  JreRShiftAssignLong(&c, 32);
  if (c != 0) {
    LibOrgBouncycastleMathRawNat_incAtWithInt_withIntArray_withInt_(7, z, 4);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224R1Field_subPInvFromWithIntArray_(IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224R1Field_initialize();
  jlong c = (IOSIntArray_Get(nil_chk(z), 0) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) + 1;
  *IOSIntArray_GetRef(z, 0) = (jint) c;
  JreRShiftAssignLong(&c, 32);
  if (c != 0) {
    c += (IOSIntArray_Get(z, 1) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M);
    *IOSIntArray_GetRef(z, 1) = (jint) c;
    JreRShiftAssignLong(&c, 32);
    c += (IOSIntArray_Get(z, 2) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M);
    *IOSIntArray_GetRef(z, 2) = (jint) c;
    JreRShiftAssignLong(&c, 32);
  }
  c += (IOSIntArray_Get(z, 3) & LibOrgBouncycastleMathEcCustomSecSecP224R1Field_M) - 1;
  *IOSIntArray_GetRef(z, 3) = (jint) c;
  JreRShiftAssignLong(&c, 32);
  if (c != 0) {
    LibOrgBouncycastleMathRawNat_decAtWithInt_withIntArray_withInt_(7, z, 4);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecP224R1Field)
