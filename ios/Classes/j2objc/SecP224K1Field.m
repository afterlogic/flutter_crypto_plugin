//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecP224K1Field.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Nat.h"
#include "Nat224.h"
#include "SecP224K1Field.h"
#include "java/math/BigInteger.h"

inline IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP224K1Field_get_PExtInv(void);
static IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExtInv;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleMathEcCustomSecSecP224K1Field, PExtInv, IOSIntArray *)

inline jint LibOrgBouncycastleMathEcCustomSecSecP224K1Field_get_P6(void);
#define LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P6 -1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP224K1Field, P6, jint)

inline jint LibOrgBouncycastleMathEcCustomSecSecP224K1Field_get_PExt13(void);
#define LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExt13 -1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP224K1Field, PExt13, jint)

inline jint LibOrgBouncycastleMathEcCustomSecSecP224K1Field_get_PInv33(void);
#define LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PInv33 6803
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP224K1Field, PInv33, jint)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleMathEcCustomSecSecP224K1Field)

IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P;
IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExt;

@implementation LibOrgBouncycastleMathEcCustomSecSecP224K1Field

+ (IOSIntArray *)P {
  return LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P;
}

+ (IOSIntArray *)PExt {
  return LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExt;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)addWithIntArray:(IOSIntArray *)x
           withIntArray:(IOSIntArray *)y
           withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_addWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)addExtWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)yy
              withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_addExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)addOneWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_addOneWithIntArray_withIntArray_(x, z);
}

+ (IOSIntArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return LibOrgBouncycastleMathEcCustomSecSecP224K1Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

+ (void)halfWithIntArray:(IOSIntArray *)x
            withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_halfWithIntArray_withIntArray_(x, z);
}

+ (void)multiplyWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_multiplyWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)multiplyAddToExtWithIntArray:(IOSIntArray *)x
                        withIntArray:(IOSIntArray *)y
                        withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(x, y, zz);
}

+ (void)negateWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_negateWithIntArray_withIntArray_(x, z);
}

+ (void)reduceWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_reduceWithIntArray_withIntArray_(xx, z);
}

+ (void)reduce32WithInt:(jint)x
           withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_reduce32WithInt_withIntArray_(x, z);
}

+ (void)squareWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_squareWithIntArray_withIntArray_(x, z);
}

+ (void)squareNWithIntArray:(IOSIntArray *)x
                    withInt:(jint)n
               withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_squareNWithIntArray_withInt_withIntArray_(x, n, z);
}

+ (void)subtractWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_subtractWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)subtractExtWithIntArray:(IOSIntArray *)xx
                   withIntArray:(IOSIntArray *)yy
                   withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_subtractExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)twiceWithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_twiceWithIntArray_withIntArray_(x, z);
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
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "P", "[I", .constantValue.asLong = 0, 0x18, -1, 20, -1, -1 },
    { "PExt", "[I", .constantValue.asLong = 0, 0x18, -1, 21, -1, -1 },
    { "PExtInv", "[I", .constantValue.asLong = 0, 0x1a, -1, 22, -1, -1 },
    { "P6", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P6, 0x1a, -1, -1, -1, -1 },
    { "PExt13", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExt13, 0x1a, -1, -1, -1, -1 },
    { "PInv33", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PInv33, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "add", "[I[I[I", "addExt", "addOne", "[I[I", "fromBigInteger", "LJavaMathBigInteger;", "half", "multiply", "multiplyAddToExt", "negate", "reduce", "reduce32", "I[I", "square", "squareN", "[II[I", "subtract", "subtractExt", "twice", &LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P, &LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExt, &LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExtInv };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecP224K1Field = { "SecP224K1Field", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 16, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecP224K1Field;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleMathEcCustomSecSecP224K1Field class]) {
    LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0xFFFFE56D, (jint) 0xFFFFFFFE, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF } count:7];
    LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExt = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0x02C23069, (jint) 0x00003526, (jint) 0x00000001, (jint) 0x00000000, (jint) 0x00000000, (jint) 0x00000000, (jint) 0x00000000, (jint) 0xFFFFCADA, (jint) 0xFFFFFFFD, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF } count:14];
    LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExtInv = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0xFD3DCF97, (jint) 0xFFFFCAD9, (jint) 0xFFFFFFFE, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0x00003525, (jint) 0x00000002 } count:9];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleMathEcCustomSecSecP224K1Field)
  }
}

@end

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_init(LibOrgBouncycastleMathEcCustomSecSecP224K1Field *self) {
  NSObject_init(self);
}

LibOrgBouncycastleMathEcCustomSecSecP224K1Field *new_LibOrgBouncycastleMathEcCustomSecSecP224K1Field_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecP224K1Field, init)
}

LibOrgBouncycastleMathEcCustomSecSecP224K1Field *create_LibOrgBouncycastleMathEcCustomSecSecP224K1Field_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecP224K1Field, init)
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_addWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat224_addWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 6) == LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P6 && LibOrgBouncycastleMathRawNat224_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(7, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_addExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_addWithInt_withIntArray_withIntArray_withIntArray_(14, xx, yy, zz);
  if (c != 0 || (IOSIntArray_Get(nil_chk(zz), 13) == LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExt13 && LibOrgBouncycastleMathRawNat_gteWithInt_withIntArray_withIntArray_(14, zz, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExt))) {
    if (LibOrgBouncycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExtInv, zz) != 0) {
      LibOrgBouncycastleMathRawNat_incAtWithInt_withIntArray_withInt_(14, zz, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExtInv->size_);
    }
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_addOneWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_incWithInt_withIntArray_withIntArray_(7, x, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 6) == LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P6 && LibOrgBouncycastleMathRawNat224_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(7, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
}

IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP224K1Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  IOSIntArray *z = LibOrgBouncycastleMathRawNat224_fromBigIntegerWithJavaMathBigInteger_(x);
  if (IOSIntArray_Get(nil_chk(z), 6) == LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P6 && LibOrgBouncycastleMathRawNat224_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P)) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(7, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
  return z;
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_halfWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  if ((IOSIntArray_Get(nil_chk(x), 0) & 1) == 0) {
    LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_withIntArray_(7, x, 0, z);
  }
  else {
    jint c = LibOrgBouncycastleMathRawNat224_addWithIntArray_withIntArray_withIntArray_(x, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P, z);
    LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_(7, z, c);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_multiplyWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat224_createExt();
  LibOrgBouncycastleMathRawNat224_mulWithIntArray_withIntArray_withIntArray_(x, y, tt);
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat224_mulAddToWithIntArray_withIntArray_withIntArray_(x, y, zz);
  if (c != 0 || (IOSIntArray_Get(nil_chk(zz), 13) == LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExt13 && LibOrgBouncycastleMathRawNat_gteWithInt_withIntArray_withIntArray_(14, zz, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExt))) {
    if (LibOrgBouncycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExtInv, zz) != 0) {
      LibOrgBouncycastleMathRawNat_incAtWithInt_withIntArray_withInt_(14, zz, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExtInv->size_);
    }
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_negateWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  if (LibOrgBouncycastleMathRawNat224_isZeroWithIntArray_(x)) {
    LibOrgBouncycastleMathRawNat224_zeroWithIntArray_(z);
  }
  else {
    LibOrgBouncycastleMathRawNat224_subWithIntArray_withIntArray_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P, x, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_reduceWithIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  jlong cc = LibOrgBouncycastleMathRawNat224_mul33AddWithInt_withIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PInv33, xx, 7, xx, 0, z, 0);
  jint c = LibOrgBouncycastleMathRawNat224_mul33DWordAddWithInt_withLong_withIntArray_withInt_(LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PInv33, cc, z, 0);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 6) == LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P6 && LibOrgBouncycastleMathRawNat224_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(7, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_reduce32WithInt_withIntArray_(jint x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  if ((x != 0 && LibOrgBouncycastleMathRawNat224_mul33WordAddWithInt_withInt_withIntArray_withInt_(LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PInv33, x, z, 0) != 0) || (IOSIntArray_Get(nil_chk(z), 6) == LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P6 && LibOrgBouncycastleMathRawNat224_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(7, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_squareWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat224_createExt();
  LibOrgBouncycastleMathRawNat224_squareWithIntArray_withIntArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_squareNWithIntArray_withInt_withIntArray_(IOSIntArray *x, jint n, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat224_createExt();
  LibOrgBouncycastleMathRawNat224_squareWithIntArray_withIntArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_reduceWithIntArray_withIntArray_(tt, z);
  while (--n > 0) {
    LibOrgBouncycastleMathRawNat224_squareWithIntArray_withIntArray_(z, tt);
    LibOrgBouncycastleMathEcCustomSecSecP224K1Field_reduceWithIntArray_withIntArray_(tt, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_subtractWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat224_subWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0) {
    LibOrgBouncycastleMathRawNat_sub33FromWithInt_withInt_withIntArray_(7, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_subtractExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_subWithInt_withIntArray_withIntArray_withIntArray_(14, xx, yy, zz);
  if (c != 0) {
    if (LibOrgBouncycastleMathRawNat_subFromWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExtInv, zz) != 0) {
      LibOrgBouncycastleMathRawNat_decAtWithInt_withIntArray_withInt_(14, zz, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PExtInv->size_);
    }
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP224K1Field_twiceWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_shiftUpBitWithInt_withIntArray_withInt_withIntArray_(7, x, 0, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 6) == LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P6 && LibOrgBouncycastleMathRawNat224_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(7, LibOrgBouncycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecP224K1Field)
