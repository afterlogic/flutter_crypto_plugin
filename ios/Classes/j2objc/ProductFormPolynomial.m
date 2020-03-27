//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/ntru/polynomial/ProductFormPolynomial.java
//

#include "Arrays.h"
#include "BigIntPolynomial.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "IntegerPolynomial.h"
#include "J2ObjC_source.h"
#include "ProductFormPolynomial.h"
#include "SparseTernaryPolynomial.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/InputStream.h"
#include "java/lang/System.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial () {
 @public
  LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f1_;
  LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f2_;
  LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f3_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial, f1_, LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial, f2_, LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial, f3_, LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *)

@implementation LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial

- (instancetype)initWithLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *)f1
                    withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *)f2
                    withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *)f3 {
  LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_(self, f1, f2, f3);
  return self;
}

+ (LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial *)generateRandomWithInt:(jint)N
                                                                                withInt:(jint)df1
                                                                                withInt:(jint)df2
                                                                                withInt:(jint)df3Ones
                                                                                withInt:(jint)df3NegOnes
                                                           withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_generateRandomWithInt_withInt_withInt_withInt_withInt_withJavaSecuritySecureRandom_(N, df1, df2, df3Ones, df3NegOnes, random);
}

+ (LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial *)fromBinaryWithByteArray:(IOSByteArray *)data
                                                                                  withInt:(jint)N
                                                                                  withInt:(jint)df1
                                                                                  withInt:(jint)df2
                                                                                  withInt:(jint)df3Ones
                                                                                  withInt:(jint)df3NegOnes {
  return LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_fromBinaryWithByteArray_withInt_withInt_withInt_withInt_withInt_(data, N, df1, df2, df3Ones, df3NegOnes);
}

+ (LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial *)fromBinaryWithJavaIoInputStream:(JavaIoInputStream *)is
                                                                                          withInt:(jint)N
                                                                                          withInt:(jint)df1
                                                                                          withInt:(jint)df2
                                                                                          withInt:(jint)df3Ones
                                                                                          withInt:(jint)df3NegOnes {
  return LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_withInt_withInt_(is, N, df1, df2, df3Ones, df3NegOnes);
}

- (IOSByteArray *)toBinary {
  IOSByteArray *f1Bin = [((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f1_)) toBinary];
  IOSByteArray *f2Bin = [((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f2_)) toBinary];
  IOSByteArray *f3Bin = [((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f3_)) toBinary];
  IOSByteArray *all = LibOrgBouncycastleUtilArrays_copyOfWithByteArray_withInt_(f1Bin, ((IOSByteArray *) nil_chk(f1Bin))->size_ + ((IOSByteArray *) nil_chk(f2Bin))->size_ + ((IOSByteArray *) nil_chk(f3Bin))->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(f2Bin, 0, all, f1Bin->size_, f2Bin->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(f3Bin, 0, all, f1Bin->size_ + f2Bin->size_, f3Bin->size_);
  return all;
}

- (LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)b {
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *c = [((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f1_)) multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:b];
  c = [((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f2_)) multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:c];
  [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(c)) addWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:[((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f3_)) multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:b]];
  return c;
}

- (LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)multWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)b {
  LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *c = [((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f1_)) multWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:b];
  c = [((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f2_)) multWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:c];
  [((LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(c)) addWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:[((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f3_)) multWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:b]];
  return c;
}

- (LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)toIntegerPolynomial {
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *i = [((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f1_)) multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:[((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f2_)) toIntegerPolynomial]];
  [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(i)) addWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:[((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f3_)) toIntegerPolynomial]];
  return i;
}

- (LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)poly2
                                                                                                                       withInt:(jint)modulus {
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *c = [self multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:poly2];
  [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(c)) modWithInt:modulus];
  return c;
}

- (NSUInteger)hash {
  jint prime = 31;
  jint result = 1;
  result = prime * result + ((f1_ == nil) ? 0 : ((jint) [((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f1_)) hash]));
  result = prime * result + ((f2_ == nil) ? 0 : ((jint) [((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f2_)) hash]));
  result = prime * result + ((f3_ == nil) ? 0 : ((jint) [((LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f3_)) hash]));
  return result;
}

- (jboolean)isEqual:(id)obj {
  if (self == obj) {
    return true;
  }
  if (obj == nil) {
    return false;
  }
  if ([self java_getClass] != [obj java_getClass]) {
    return false;
  }
  LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial *other = (LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial *) cast_chk(obj, [LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial class]);
  if (f1_ == nil) {
    if (other->f1_ != nil) {
      return false;
    }
  }
  else if (![f1_ isEqual:other->f1_]) {
    return false;
  }
  if (f2_ == nil) {
    if (other->f2_ != nil) {
      return false;
    }
  }
  else if (![f2_ isEqual:other->f2_]) {
    return false;
  }
  if (f3_ == nil) {
    if (other->f3_ != nil) {
      return false;
    }
  }
  else if (![f3_ isEqual:other->f3_]) {
    return false;
  }
  return true;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial;", 0x9, 3, 4, 5, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial;", 0x9, 3, 6, 5, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;", 0x1, 7, 9, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;", 0x1, 7, 10, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 11, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 12, 13, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial:withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial:withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial:);
  methods[1].selector = @selector(generateRandomWithInt:withInt:withInt:withInt:withInt:withJavaSecuritySecureRandom:);
  methods[2].selector = @selector(fromBinaryWithByteArray:withInt:withInt:withInt:withInt:withInt:);
  methods[3].selector = @selector(fromBinaryWithJavaIoInputStream:withInt:withInt:withInt:withInt:withInt:);
  methods[4].selector = @selector(toBinary);
  methods[5].selector = @selector(multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:);
  methods[6].selector = @selector(multWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:);
  methods[7].selector = @selector(toIntegerPolynomial);
  methods[8].selector = @selector(multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:withInt:);
  methods[9].selector = @selector(hash);
  methods[10].selector = @selector(isEqual:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "f1_", "LLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "f2_", "LLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "f3_", "LLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial;LLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial;LLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial;", "generateRandom", "IIIIILJavaSecuritySecureRandom;", "fromBinary", "[BIIIII", "LJavaIoIOException;", "LJavaIoInputStream;IIIII", "mult", "LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;", "LLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;", "LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;I", "hashCode", "equals", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial = { "ProductFormPolynomial", "lib.org.bouncycastle.pqc.math.ntru.polynomial", ptrTable, methods, fields, 7, 0x1, 11, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial;
}

@end

void LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial *self, LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f1, LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f2, LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f3) {
  NSObject_init(self);
  self->f1_ = f1;
  self->f2_ = f2;
  self->f3_ = f3;
}

LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial *new_LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f1, LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f2, LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f3) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial, initWithLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_, f1, f2, f3)
}

LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial *create_LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f1, LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f2, LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f3) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial, initWithLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_, f1, f2, f3)
}

LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial *LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_generateRandomWithInt_withInt_withInt_withInt_withInt_withJavaSecuritySecureRandom_(jint N, jint df1, jint df2, jint df3Ones, jint df3NegOnes, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_initialize();
  LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f1 = LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_generateRandomWithInt_withInt_withInt_withJavaSecuritySecureRandom_(N, df1, df1, random);
  LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f2 = LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_generateRandomWithInt_withInt_withInt_withJavaSecuritySecureRandom_(N, df2, df2, random);
  LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f3 = LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_generateRandomWithInt_withInt_withInt_withJavaSecuritySecureRandom_(N, df3Ones, df3NegOnes, random);
  return new_LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_(f1, f2, f3);
}

LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial *LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_fromBinaryWithByteArray_withInt_withInt_withInt_withInt_withInt_(IOSByteArray *data, jint N, jint df1, jint df2, jint df3Ones, jint df3NegOnes) {
  LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_initialize();
  return LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_withInt_withInt_(new_JavaIoByteArrayInputStream_initWithByteArray_(data), N, df1, df2, df3Ones, df3NegOnes);
}

LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial *LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_withInt_withInt_(JavaIoInputStream *is, jint N, jint df1, jint df2, jint df3Ones, jint df3NegOnes) {
  LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_initialize();
  LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f1;
  f1 = LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_(is, N, df1, df1);
  LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f2 = LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_(is, N, df2, df2);
  LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f3 = LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_(is, N, df3Ones, df3NegOnes);
  return new_LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_(f1, f2, f3);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial)
