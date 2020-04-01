//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecP128R1Field.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Nat.h"
#include "Nat128.h"
#include "Nat256.h"
#include "SecP128R1Field.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleMathEcCustomSecSecP128R1Field ()

+ (void)addPInvToWithIntArray:(IOSIntArray *)z;

+ (void)subPInvFromWithIntArray:(IOSIntArray *)z;

@end

inline jlong LibOrgBouncycastleMathEcCustomSecSecP128R1Field_get_M(void);
#define LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M 4294967295LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP128R1Field, M, jlong)

inline IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP128R1Field_get_PExtInv(void);
static IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExtInv;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleMathEcCustomSecSecP128R1Field, PExtInv, IOSIntArray *)

inline jint LibOrgBouncycastleMathEcCustomSecSecP128R1Field_get_P3s1(void);
#define LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P3s1 2147483646
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP128R1Field, P3s1, jint)

inline jint LibOrgBouncycastleMathEcCustomSecSecP128R1Field_get_PExt7s1(void);
#define LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExt7s1 2147483646
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP128R1Field, PExt7s1, jint)

__attribute__((unused)) static void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_addPInvToWithIntArray_(IOSIntArray *z);

__attribute__((unused)) static void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_subPInvFromWithIntArray_(IOSIntArray *z);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleMathEcCustomSecSecP128R1Field)

IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P;
IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExt;

@implementation LibOrgBouncycastleMathEcCustomSecSecP128R1Field

+ (IOSIntArray *)P {
  return LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P;
}

+ (IOSIntArray *)PExt {
  return LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExt;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)addWithIntArray:(IOSIntArray *)x
           withIntArray:(IOSIntArray *)y
           withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_addWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)addExtWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)yy
              withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_addExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)addOneWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_addOneWithIntArray_withIntArray_(x, z);
}

+ (IOSIntArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return LibOrgBouncycastleMathEcCustomSecSecP128R1Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

+ (void)halfWithIntArray:(IOSIntArray *)x
            withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_halfWithIntArray_withIntArray_(x, z);
}

+ (void)multiplyWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_multiplyWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)multiplyAddToExtWithIntArray:(IOSIntArray *)x
                        withIntArray:(IOSIntArray *)y
                        withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(x, y, zz);
}

+ (void)negateWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_negateWithIntArray_withIntArray_(x, z);
}

+ (void)reduceWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_reduceWithIntArray_withIntArray_(xx, z);
}

+ (void)reduce32WithInt:(jint)x
           withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_reduce32WithInt_withIntArray_(x, z);
}

+ (void)squareWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_squareWithIntArray_withIntArray_(x, z);
}

+ (void)squareNWithIntArray:(IOSIntArray *)x
                    withInt:(jint)n
               withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_squareNWithIntArray_withInt_withIntArray_(x, n, z);
}

+ (void)subtractWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_subtractWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)subtractExtWithIntArray:(IOSIntArray *)xx
                   withIntArray:(IOSIntArray *)yy
                   withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_subtractExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)twiceWithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_twiceWithIntArray_withIntArray_(x, z);
}

+ (void)addPInvToWithIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_addPInvToWithIntArray_(z);
}

+ (void)subPInvFromWithIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_subPInvFromWithIntArray_(z);
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
    { "M", "J", .constantValue.asLong = LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M, 0x1a, -1, -1, -1, -1 },
    { "P", "[I", .constantValue.asLong = 0, 0x18, -1, 23, -1, -1 },
    { "PExt", "[I", .constantValue.asLong = 0, 0x18, -1, 24, -1, -1 },
    { "PExtInv", "[I", .constantValue.asLong = 0, 0x1a, -1, 25, -1, -1 },
    { "P3s1", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P3s1, 0x1a, -1, -1, -1, -1 },
    { "PExt7s1", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExt7s1, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "add", "[I[I[I", "addExt", "addOne", "[I[I", "fromBigInteger", "LJavaMathBigInteger;", "half", "multiply", "multiplyAddToExt", "negate", "reduce", "reduce32", "I[I", "square", "squareN", "[II[I", "subtract", "subtractExt", "twice", "addPInvTo", "[I", "subPInvFrom", &LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P, &LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExt, &LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExtInv };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecP128R1Field = { "SecP128R1Field", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 18, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecP128R1Field;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleMathEcCustomSecSecP128R1Field class]) {
    LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFD } count:4];
    LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExt = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0x00000001, (jint) 0x00000000, (jint) 0x00000000, (jint) 0x00000004, (jint) 0xFFFFFFFE, (jint) 0xFFFFFFFF, (jint) 0x00000003, (jint) 0xFFFFFFFC } count:8];
    LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExtInv = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFB, (jint) 0x00000001, (jint) 0x00000000, (jint) 0xFFFFFFFC, (jint) 0x00000003 } count:8];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleMathEcCustomSecSecP128R1Field)
  }
}

@end

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_init(LibOrgBouncycastleMathEcCustomSecSecP128R1Field *self) {
  NSObject_init(self);
}

LibOrgBouncycastleMathEcCustomSecSecP128R1Field *new_LibOrgBouncycastleMathEcCustomSecSecP128R1Field_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecP128R1Field, init)
}

LibOrgBouncycastleMathEcCustomSecSecP128R1Field *create_LibOrgBouncycastleMathEcCustomSecSecP128R1Field_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecP128R1Field, init)
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_addWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat128_addWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0 || ((JreURShift32(IOSIntArray_Get(nil_chk(z), 3), 1)) >= LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P3s1 && LibOrgBouncycastleMathRawNat128_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P))) {
    LibOrgBouncycastleMathEcCustomSecSecP128R1Field_addPInvToWithIntArray_(z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_addExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat256_addWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
  if (c != 0 || ((JreURShift32(IOSIntArray_Get(nil_chk(zz), 7), 1)) >= LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExt7s1 && LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(zz, LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExt))) {
    LibOrgBouncycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExtInv, zz);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_addOneWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_incWithInt_withIntArray_withIntArray_(4, x, z);
  if (c != 0 || ((JreURShift32(IOSIntArray_Get(nil_chk(z), 3), 1)) >= LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P3s1 && LibOrgBouncycastleMathRawNat128_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P))) {
    LibOrgBouncycastleMathEcCustomSecSecP128R1Field_addPInvToWithIntArray_(z);
  }
}

IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP128R1Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  IOSIntArray *z = LibOrgBouncycastleMathRawNat128_fromBigIntegerWithJavaMathBigInteger_(x);
  if ((JreURShift32(IOSIntArray_Get(nil_chk(z), 3), 1)) >= LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P3s1 && LibOrgBouncycastleMathRawNat128_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P)) {
    LibOrgBouncycastleMathRawNat128_subFromWithIntArray_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P, z);
  }
  return z;
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_halfWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  if ((IOSIntArray_Get(nil_chk(x), 0) & 1) == 0) {
    LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_withIntArray_(4, x, 0, z);
  }
  else {
    jint c = LibOrgBouncycastleMathRawNat128_addWithIntArray_withIntArray_withIntArray_(x, LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P, z);
    LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_(4, z, c);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_multiplyWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat128_createExt();
  LibOrgBouncycastleMathRawNat128_mulWithIntArray_withIntArray_withIntArray_(x, y, tt);
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat128_mulAddToWithIntArray_withIntArray_withIntArray_(x, y, zz);
  if (c != 0 || ((JreURShift32(IOSIntArray_Get(nil_chk(zz), 7), 1)) >= LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExt7s1 && LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(zz, LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExt))) {
    LibOrgBouncycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExtInv, zz);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_negateWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  if (LibOrgBouncycastleMathRawNat128_isZeroWithIntArray_(x)) {
    LibOrgBouncycastleMathRawNat128_zeroWithIntArray_(z);
  }
  else {
    LibOrgBouncycastleMathRawNat128_subWithIntArray_withIntArray_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P, x, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_reduceWithIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  jlong x0 = IOSIntArray_Get(nil_chk(xx), 0) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M;
  jlong x1 = IOSIntArray_Get(xx, 1) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M;
  jlong x2 = IOSIntArray_Get(xx, 2) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M;
  jlong x3 = IOSIntArray_Get(xx, 3) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M;
  jlong x4 = IOSIntArray_Get(xx, 4) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M;
  jlong x5 = IOSIntArray_Get(xx, 5) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M;
  jlong x6 = IOSIntArray_Get(xx, 6) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M;
  jlong x7 = IOSIntArray_Get(xx, 7) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M;
  x3 += x7;
  x6 += (JreLShift64(x7, 1));
  x2 += x6;
  x5 += (JreLShift64(x6, 1));
  x1 += x5;
  x4 += (JreLShift64(x5, 1));
  x0 += x4;
  x3 += (JreLShift64(x4, 1));
  *IOSIntArray_GetRef(nil_chk(z), 0) = (jint) x0;
  x1 += (JreURShift64(x0, 32));
  *IOSIntArray_GetRef(z, 1) = (jint) x1;
  x2 += (JreURShift64(x1, 32));
  *IOSIntArray_GetRef(z, 2) = (jint) x2;
  x3 += (JreURShift64(x2, 32));
  *IOSIntArray_GetRef(z, 3) = (jint) x3;
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_reduce32WithInt_withIntArray_((jint) (JreURShift64(x3, 32)), z);
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_reduce32WithInt_withIntArray_(jint x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  while (x != 0) {
    jlong c;
    jlong x4 = x & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M;
    c = (IOSIntArray_Get(nil_chk(z), 0) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M) + x4;
    *IOSIntArray_GetRef(z, 0) = (jint) c;
    JreRShiftAssignLong(&c, 32);
    if (c != 0) {
      c += (IOSIntArray_Get(z, 1) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M);
      *IOSIntArray_GetRef(z, 1) = (jint) c;
      JreRShiftAssignLong(&c, 32);
      c += (IOSIntArray_Get(z, 2) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M);
      *IOSIntArray_GetRef(z, 2) = (jint) c;
      JreRShiftAssignLong(&c, 32);
    }
    c += (IOSIntArray_Get(z, 3) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M) + (JreLShift64(x4, 1));
    *IOSIntArray_GetRef(z, 3) = (jint) c;
    JreRShiftAssignLong(&c, 32);
    x = (jint) c;
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_squareWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat128_createExt();
  LibOrgBouncycastleMathRawNat128_squareWithIntArray_withIntArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_squareNWithIntArray_withInt_withIntArray_(IOSIntArray *x, jint n, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat128_createExt();
  LibOrgBouncycastleMathRawNat128_squareWithIntArray_withIntArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_reduceWithIntArray_withIntArray_(tt, z);
  while (--n > 0) {
    LibOrgBouncycastleMathRawNat128_squareWithIntArray_withIntArray_(z, tt);
    LibOrgBouncycastleMathEcCustomSecSecP128R1Field_reduceWithIntArray_withIntArray_(tt, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_subtractWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat128_subWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0) {
    LibOrgBouncycastleMathEcCustomSecSecP128R1Field_subPInvFromWithIntArray_(z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_subtractExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_subWithInt_withIntArray_withIntArray_withIntArray_(10, xx, yy, zz);
  if (c != 0) {
    LibOrgBouncycastleMathRawNat_subFromWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP128R1Field_PExtInv, zz);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_twiceWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_shiftUpBitWithInt_withIntArray_withInt_withIntArray_(4, x, 0, z);
  if (c != 0 || ((JreURShift32(IOSIntArray_Get(nil_chk(z), 3), 1)) >= LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P3s1 && LibOrgBouncycastleMathRawNat128_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP128R1Field_P))) {
    LibOrgBouncycastleMathEcCustomSecSecP128R1Field_addPInvToWithIntArray_(z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_addPInvToWithIntArray_(IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  jlong c = (IOSIntArray_Get(nil_chk(z), 0) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M) + 1;
  *IOSIntArray_GetRef(z, 0) = (jint) c;
  JreRShiftAssignLong(&c, 32);
  if (c != 0) {
    c += (IOSIntArray_Get(z, 1) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M);
    *IOSIntArray_GetRef(z, 1) = (jint) c;
    JreRShiftAssignLong(&c, 32);
    c += (IOSIntArray_Get(z, 2) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M);
    *IOSIntArray_GetRef(z, 2) = (jint) c;
    JreRShiftAssignLong(&c, 32);
  }
  c += (IOSIntArray_Get(z, 3) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M) + 2;
  *IOSIntArray_GetRef(z, 3) = (jint) c;
}

void LibOrgBouncycastleMathEcCustomSecSecP128R1Field_subPInvFromWithIntArray_(IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP128R1Field_initialize();
  jlong c = (IOSIntArray_Get(nil_chk(z), 0) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M) - 1;
  *IOSIntArray_GetRef(z, 0) = (jint) c;
  JreRShiftAssignLong(&c, 32);
  if (c != 0) {
    c += (IOSIntArray_Get(z, 1) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M);
    *IOSIntArray_GetRef(z, 1) = (jint) c;
    JreRShiftAssignLong(&c, 32);
    c += (IOSIntArray_Get(z, 2) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M);
    *IOSIntArray_GetRef(z, 2) = (jint) c;
    JreRShiftAssignLong(&c, 32);
  }
  c += (IOSIntArray_Get(z, 3) & LibOrgBouncycastleMathEcCustomSecSecP128R1Field_M) - 2;
  *IOSIntArray_GetRef(z, 3) = (jint) c;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecP128R1Field)