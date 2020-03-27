//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/raw/Mont256.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Mont256.h"
#include "Nat256.h"

inline jlong LibOrgBouncycastleMathRawMont256_get_M(void);
#define LibOrgBouncycastleMathRawMont256_M 4294967295LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathRawMont256, M, jlong)

@implementation LibOrgBouncycastleMathRawMont256

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathRawMont256_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jint)inverse32WithInt:(jint)x {
  return LibOrgBouncycastleMathRawMont256_inverse32WithInt_(x);
}

+ (void)multAddWithIntArray:(IOSIntArray *)x
               withIntArray:(IOSIntArray *)y
               withIntArray:(IOSIntArray *)z
               withIntArray:(IOSIntArray *)m
                    withInt:(jint)mInv32 {
  LibOrgBouncycastleMathRawMont256_multAddWithIntArray_withIntArray_withIntArray_withIntArray_withInt_(x, y, z, m, mInv32);
}

+ (void)multAddXFWithIntArray:(IOSIntArray *)x
                 withIntArray:(IOSIntArray *)y
                 withIntArray:(IOSIntArray *)z
                 withIntArray:(IOSIntArray *)m {
  LibOrgBouncycastleMathRawMont256_multAddXFWithIntArray_withIntArray_withIntArray_withIntArray_(x, y, z, m);
}

+ (void)reduceWithIntArray:(IOSIntArray *)z
              withIntArray:(IOSIntArray *)m
                   withInt:(jint)mInv32 {
  LibOrgBouncycastleMathRawMont256_reduceWithIntArray_withIntArray_withInt_(z, m, mInv32);
}

+ (void)reduceXFWithIntArray:(IOSIntArray *)z
                withIntArray:(IOSIntArray *)m {
  LibOrgBouncycastleMathRawMont256_reduceXFWithIntArray_withIntArray_(z, m);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 8, 9, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(inverse32WithInt:);
  methods[2].selector = @selector(multAddWithIntArray:withIntArray:withIntArray:withIntArray:withInt:);
  methods[3].selector = @selector(multAddXFWithIntArray:withIntArray:withIntArray:withIntArray:);
  methods[4].selector = @selector(reduceWithIntArray:withIntArray:withInt:);
  methods[5].selector = @selector(reduceXFWithIntArray:withIntArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "M", "J", .constantValue.asLong = LibOrgBouncycastleMathRawMont256_M, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "inverse32", "I", "multAdd", "[I[I[I[II", "multAddXF", "[I[I[I[I", "reduce", "[I[II", "reduceXF", "[I[I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathRawMont256 = { "Mont256", "lib.org.bouncycastle.math.raw", ptrTable, methods, fields, 7, 0x401, 6, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathRawMont256;
}

@end

void LibOrgBouncycastleMathRawMont256_init(LibOrgBouncycastleMathRawMont256 *self) {
  NSObject_init(self);
}

jint LibOrgBouncycastleMathRawMont256_inverse32WithInt_(jint x) {
  LibOrgBouncycastleMathRawMont256_initialize();
  jint z = x;
  z *= 2 - x * z;
  z *= 2 - x * z;
  z *= 2 - x * z;
  z *= 2 - x * z;
  return z;
}

void LibOrgBouncycastleMathRawMont256_multAddWithIntArray_withIntArray_withIntArray_withIntArray_withInt_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z, IOSIntArray *m, jint mInv32) {
  LibOrgBouncycastleMathRawMont256_initialize();
  jint z_8 = 0;
  jlong y_0 = IOSIntArray_Get(nil_chk(y), 0) & LibOrgBouncycastleMathRawMont256_M;
  for (jint i = 0; i < 8; ++i) {
    jlong z_0 = IOSIntArray_Get(nil_chk(z), 0) & LibOrgBouncycastleMathRawMont256_M;
    jlong x_i = IOSIntArray_Get(nil_chk(x), i) & LibOrgBouncycastleMathRawMont256_M;
    jlong prod1 = x_i * y_0;
    jlong carry = (prod1 & LibOrgBouncycastleMathRawMont256_M) + z_0;
    jlong t = ((jint) carry * mInv32) & LibOrgBouncycastleMathRawMont256_M;
    jlong prod2 = t * (IOSIntArray_Get(nil_chk(m), 0) & LibOrgBouncycastleMathRawMont256_M);
    carry += (prod2 & LibOrgBouncycastleMathRawMont256_M);
    carry = (JreURShift64(carry, 32)) + (JreURShift64(prod1, 32)) + (JreURShift64(prod2, 32));
    for (jint j = 1; j < 8; ++j) {
      prod1 = x_i * (IOSIntArray_Get(y, j) & LibOrgBouncycastleMathRawMont256_M);
      prod2 = t * (IOSIntArray_Get(m, j) & LibOrgBouncycastleMathRawMont256_M);
      carry += (prod1 & LibOrgBouncycastleMathRawMont256_M) + (prod2 & LibOrgBouncycastleMathRawMont256_M) + (IOSIntArray_Get(z, j) & LibOrgBouncycastleMathRawMont256_M);
      *IOSIntArray_GetRef(z, j - 1) = (jint) carry;
      carry = (JreURShift64(carry, 32)) + (JreURShift64(prod1, 32)) + (JreURShift64(prod2, 32));
    }
    carry += (z_8 & LibOrgBouncycastleMathRawMont256_M);
    *IOSIntArray_GetRef(z, 7) = (jint) carry;
    z_8 = (jint) (JreURShift64(carry, 32));
  }
  if (z_8 != 0 || LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, m)) {
    LibOrgBouncycastleMathRawNat256_subWithIntArray_withIntArray_withIntArray_(z, m, z);
  }
}

void LibOrgBouncycastleMathRawMont256_multAddXFWithIntArray_withIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z, IOSIntArray *m) {
  LibOrgBouncycastleMathRawMont256_initialize();
  jint z_8 = 0;
  jlong y_0 = IOSIntArray_Get(nil_chk(y), 0) & LibOrgBouncycastleMathRawMont256_M;
  for (jint i = 0; i < 8; ++i) {
    jlong x_i = IOSIntArray_Get(nil_chk(x), i) & LibOrgBouncycastleMathRawMont256_M;
    jlong carry = x_i * y_0 + (IOSIntArray_Get(nil_chk(z), 0) & LibOrgBouncycastleMathRawMont256_M);
    jlong t = carry & LibOrgBouncycastleMathRawMont256_M;
    carry = (JreURShift64(carry, 32)) + t;
    for (jint j = 1; j < 8; ++j) {
      jlong prod1 = x_i * (IOSIntArray_Get(y, j) & LibOrgBouncycastleMathRawMont256_M);
      jlong prod2 = t * (IOSIntArray_Get(nil_chk(m), j) & LibOrgBouncycastleMathRawMont256_M);
      carry += (prod1 & LibOrgBouncycastleMathRawMont256_M) + (prod2 & LibOrgBouncycastleMathRawMont256_M) + (IOSIntArray_Get(z, j) & LibOrgBouncycastleMathRawMont256_M);
      *IOSIntArray_GetRef(z, j - 1) = (jint) carry;
      carry = (JreURShift64(carry, 32)) + (JreURShift64(prod1, 32)) + (JreURShift64(prod2, 32));
    }
    carry += (z_8 & LibOrgBouncycastleMathRawMont256_M);
    *IOSIntArray_GetRef(z, 7) = (jint) carry;
    z_8 = (jint) (JreURShift64(carry, 32));
  }
  if (z_8 != 0 || LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, m)) {
    LibOrgBouncycastleMathRawNat256_subWithIntArray_withIntArray_withIntArray_(z, m, z);
  }
}

void LibOrgBouncycastleMathRawMont256_reduceWithIntArray_withIntArray_withInt_(IOSIntArray *z, IOSIntArray *m, jint mInv32) {
  LibOrgBouncycastleMathRawMont256_initialize();
  for (jint i = 0; i < 8; ++i) {
    jint z_0 = IOSIntArray_Get(nil_chk(z), 0);
    jlong t = (z_0 * mInv32) & LibOrgBouncycastleMathRawMont256_M;
    jlong carry = t * (IOSIntArray_Get(nil_chk(m), 0) & LibOrgBouncycastleMathRawMont256_M) + (z_0 & LibOrgBouncycastleMathRawMont256_M);
    JreURShiftAssignLong(&carry, 32);
    for (jint j = 1; j < 8; ++j) {
      carry += t * (IOSIntArray_Get(m, j) & LibOrgBouncycastleMathRawMont256_M) + (IOSIntArray_Get(z, j) & LibOrgBouncycastleMathRawMont256_M);
      *IOSIntArray_GetRef(z, j - 1) = (jint) carry;
      JreURShiftAssignLong(&carry, 32);
    }
    *IOSIntArray_GetRef(z, 7) = (jint) carry;
  }
  if (LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, m)) {
    LibOrgBouncycastleMathRawNat256_subWithIntArray_withIntArray_withIntArray_(z, m, z);
  }
}

void LibOrgBouncycastleMathRawMont256_reduceXFWithIntArray_withIntArray_(IOSIntArray *z, IOSIntArray *m) {
  LibOrgBouncycastleMathRawMont256_initialize();
  for (jint i = 0; i < 8; ++i) {
    jint z_0 = IOSIntArray_Get(nil_chk(z), 0);
    jlong t = z_0 & LibOrgBouncycastleMathRawMont256_M;
    jlong carry = t;
    for (jint j = 1; j < 8; ++j) {
      carry += t * (IOSIntArray_Get(nil_chk(m), j) & LibOrgBouncycastleMathRawMont256_M) + (IOSIntArray_Get(z, j) & LibOrgBouncycastleMathRawMont256_M);
      *IOSIntArray_GetRef(z, j - 1) = (jint) carry;
      JreURShiftAssignLong(&carry, 32);
    }
    *IOSIntArray_GetRef(z, 7) = (jint) carry;
  }
  if (LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, m)) {
    LibOrgBouncycastleMathRawNat256_subWithIntArray_withIntArray_withIntArray_(z, m, z);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathRawMont256)
