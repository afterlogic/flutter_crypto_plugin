//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/linearalgebra/Permutation.java
//

#include "Arrays.h"
#include "IOSPrimitiveArray.h"
#include "IntUtils.h"
#include "IntegerFunctions.h"
#include "J2ObjC_source.h"
#include "LittleEndianConversions.h"
#include "Permutation.h"
#include "RandUtils.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastlePqcMathLinearalgebraPermutation () {
 @public
  IOSIntArray *perm_;
}

- (jboolean)isPermutationWithIntArray:(IOSIntArray *)perm;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcMathLinearalgebraPermutation, perm_, IOSIntArray *)

__attribute__((unused)) static jboolean LibOrgBouncycastlePqcMathLinearalgebraPermutation_isPermutationWithIntArray_(LibOrgBouncycastlePqcMathLinearalgebraPermutation *self, IOSIntArray *perm);

@implementation LibOrgBouncycastlePqcMathLinearalgebraPermutation

- (instancetype)initWithInt:(jint)n {
  LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_(self, n);
  return self;
}

- (instancetype)initWithIntArray:(IOSIntArray *)perm {
  LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithIntArray_(self, perm);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)enc {
  LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithByteArray_(self, enc);
  return self;
}

- (instancetype)initWithInt:(jint)n
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)sr {
  LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_withJavaSecuritySecureRandom_(self, n, sr);
  return self;
}

- (IOSByteArray *)getEncoded {
  jint n = ((IOSIntArray *) nil_chk(perm_))->size_;
  jint size = LibOrgBouncycastlePqcMathLinearalgebraIntegerFunctions_ceilLog256WithInt_(n - 1);
  IOSByteArray *result = [IOSByteArray newArrayWithLength:4 + n * size];
  LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_I2OSPWithInt_withByteArray_withInt_(n, result, 0);
  for (jint i = 0; i < n; i++) {
    LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_I2OSPWithInt_withByteArray_withInt_withInt_(IOSIntArray_Get(nil_chk(perm_), i), result, 4 + i * size, size);
  }
  return result;
}

- (IOSIntArray *)getVector {
  return LibOrgBouncycastlePqcMathLinearalgebraIntUtils_cloneWithIntArray_(perm_);
}

- (LibOrgBouncycastlePqcMathLinearalgebraPermutation *)computeInverse {
  LibOrgBouncycastlePqcMathLinearalgebraPermutation *result = new_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_(((IOSIntArray *) nil_chk(perm_))->size_);
  for (jint i = ((IOSIntArray *) nil_chk(perm_))->size_ - 1; i >= 0; i--) {
    *IOSIntArray_GetRef(result->perm_, IOSIntArray_Get(perm_, i)) = i;
  }
  return result;
}

- (LibOrgBouncycastlePqcMathLinearalgebraPermutation *)rightMultiplyWithLibOrgBouncycastlePqcMathLinearalgebraPermutation:(LibOrgBouncycastlePqcMathLinearalgebraPermutation *)p {
  if (((IOSIntArray *) nil_chk(((LibOrgBouncycastlePqcMathLinearalgebraPermutation *) nil_chk(p))->perm_))->size_ != perm_->size_) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"length mismatch");
  }
  LibOrgBouncycastlePqcMathLinearalgebraPermutation *result = new_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_(perm_->size_);
  for (jint i = ((IOSIntArray *) nil_chk(perm_))->size_ - 1; i >= 0; i--) {
    *IOSIntArray_GetRef(result->perm_, i) = IOSIntArray_Get(perm_, IOSIntArray_Get(p->perm_, i));
  }
  return result;
}

- (jboolean)isEqual:(id)other {
  if (!([other isKindOfClass:[LibOrgBouncycastlePqcMathLinearalgebraPermutation class]])) {
    return false;
  }
  LibOrgBouncycastlePqcMathLinearalgebraPermutation *otherPerm = (LibOrgBouncycastlePqcMathLinearalgebraPermutation *) cast_chk(other, [LibOrgBouncycastlePqcMathLinearalgebraPermutation class]);
  return LibOrgBouncycastlePqcMathLinearalgebraIntUtils_equalsWithIntArray_withIntArray_(perm_, ((LibOrgBouncycastlePqcMathLinearalgebraPermutation *) nil_chk(otherPerm))->perm_);
}

- (NSString *)description {
  NSString *result = JreStrcat("CI", '[', IOSIntArray_Get(nil_chk(perm_), 0));
  for (jint i = 1; i < perm_->size_; i++) {
    (void) JreStrAppendStrong(&result, "$I", @", ", IOSIntArray_Get(perm_, i));
  }
  (void) JreStrAppendStrong(&result, "$", @"]");
  return result;
}

- (NSUInteger)hash {
  return LibOrgBouncycastleUtilArrays_hashCodeWithIntArray_(perm_);
}

- (jboolean)isPermutationWithIntArray:(IOSIntArray *)perm {
  return LibOrgBouncycastlePqcMathLinearalgebraPermutation_isPermutationWithIntArray_(self, perm);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathLinearalgebraPermutation;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathLinearalgebraPermutation;", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 8, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 9, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 10, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:);
  methods[1].selector = @selector(initWithIntArray:);
  methods[2].selector = @selector(initWithByteArray:);
  methods[3].selector = @selector(initWithInt:withJavaSecuritySecureRandom:);
  methods[4].selector = @selector(getEncoded);
  methods[5].selector = @selector(getVector);
  methods[6].selector = @selector(computeInverse);
  methods[7].selector = @selector(rightMultiplyWithLibOrgBouncycastlePqcMathLinearalgebraPermutation:);
  methods[8].selector = @selector(isEqual:);
  methods[9].selector = @selector(description);
  methods[10].selector = @selector(hash);
  methods[11].selector = @selector(isPermutationWithIntArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "perm_", "[I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I", "[I", "[B", "ILJavaSecuritySecureRandom;", "rightMultiply", "LLibOrgBouncycastlePqcMathLinearalgebraPermutation;", "equals", "LNSObject;", "toString", "hashCode", "isPermutation" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcMathLinearalgebraPermutation = { "Permutation", "lib.org.bouncycastle.pqc.math.linearalgebra", ptrTable, methods, fields, 7, 0x1, 12, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcMathLinearalgebraPermutation;
}

@end

void LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_(LibOrgBouncycastlePqcMathLinearalgebraPermutation *self, jint n) {
  NSObject_init(self);
  if (n <= 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"invalid length");
  }
  self->perm_ = [IOSIntArray newArrayWithLength:n];
  for (jint i = n - 1; i >= 0; i--) {
    *IOSIntArray_GetRef(self->perm_, i) = i;
  }
}

LibOrgBouncycastlePqcMathLinearalgebraPermutation *new_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_(jint n) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcMathLinearalgebraPermutation, initWithInt_, n)
}

LibOrgBouncycastlePqcMathLinearalgebraPermutation *create_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_(jint n) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcMathLinearalgebraPermutation, initWithInt_, n)
}

void LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithIntArray_(LibOrgBouncycastlePqcMathLinearalgebraPermutation *self, IOSIntArray *perm) {
  NSObject_init(self);
  if (!LibOrgBouncycastlePqcMathLinearalgebraPermutation_isPermutationWithIntArray_(self, perm)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"array is not a permutation vector");
  }
  self->perm_ = LibOrgBouncycastlePqcMathLinearalgebraIntUtils_cloneWithIntArray_(perm);
}

LibOrgBouncycastlePqcMathLinearalgebraPermutation *new_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithIntArray_(IOSIntArray *perm) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcMathLinearalgebraPermutation, initWithIntArray_, perm)
}

LibOrgBouncycastlePqcMathLinearalgebraPermutation *create_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithIntArray_(IOSIntArray *perm) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcMathLinearalgebraPermutation, initWithIntArray_, perm)
}

void LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithByteArray_(LibOrgBouncycastlePqcMathLinearalgebraPermutation *self, IOSByteArray *enc) {
  NSObject_init(self);
  if (((IOSByteArray *) nil_chk(enc))->size_ <= 4) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"invalid encoding");
  }
  jint n = LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_OS2IPWithByteArray_withInt_(enc, 0);
  jint size = LibOrgBouncycastlePqcMathLinearalgebraIntegerFunctions_ceilLog256WithInt_(n - 1);
  if (enc->size_ != 4 + n * size) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"invalid encoding");
  }
  self->perm_ = [IOSIntArray newArrayWithLength:n];
  for (jint i = 0; i < n; i++) {
    *IOSIntArray_GetRef(nil_chk(self->perm_), i) = LibOrgBouncycastlePqcMathLinearalgebraLittleEndianConversions_OS2IPWithByteArray_withInt_withInt_(enc, 4 + i * size, size);
  }
  if (!LibOrgBouncycastlePqcMathLinearalgebraPermutation_isPermutationWithIntArray_(self, self->perm_)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"invalid encoding");
  }
}

LibOrgBouncycastlePqcMathLinearalgebraPermutation *new_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithByteArray_(IOSByteArray *enc) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcMathLinearalgebraPermutation, initWithByteArray_, enc)
}

LibOrgBouncycastlePqcMathLinearalgebraPermutation *create_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithByteArray_(IOSByteArray *enc) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcMathLinearalgebraPermutation, initWithByteArray_, enc)
}

void LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_withJavaSecuritySecureRandom_(LibOrgBouncycastlePqcMathLinearalgebraPermutation *self, jint n, JavaSecuritySecureRandom *sr) {
  NSObject_init(self);
  if (n <= 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"invalid length");
  }
  self->perm_ = [IOSIntArray newArrayWithLength:n];
  IOSIntArray *help = [IOSIntArray newArrayWithLength:n];
  for (jint i = 0; i < n; i++) {
    *IOSIntArray_GetRef(help, i) = i;
  }
  jint k = n;
  for (jint j = 0; j < n; j++) {
    jint i = LibOrgBouncycastlePqcMathLinearalgebraRandUtils_nextIntWithJavaSecuritySecureRandom_withInt_(sr, k);
    k--;
    *IOSIntArray_GetRef(nil_chk(self->perm_), j) = IOSIntArray_Get(help, i);
    *IOSIntArray_GetRef(help, i) = IOSIntArray_Get(help, k);
  }
}

LibOrgBouncycastlePqcMathLinearalgebraPermutation *new_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_withJavaSecuritySecureRandom_(jint n, JavaSecuritySecureRandom *sr) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcMathLinearalgebraPermutation, initWithInt_withJavaSecuritySecureRandom_, n, sr)
}

LibOrgBouncycastlePqcMathLinearalgebraPermutation *create_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_withJavaSecuritySecureRandom_(jint n, JavaSecuritySecureRandom *sr) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcMathLinearalgebraPermutation, initWithInt_withJavaSecuritySecureRandom_, n, sr)
}

jboolean LibOrgBouncycastlePqcMathLinearalgebraPermutation_isPermutationWithIntArray_(LibOrgBouncycastlePqcMathLinearalgebraPermutation *self, IOSIntArray *perm) {
  jint n = ((IOSIntArray *) nil_chk(perm))->size_;
  IOSBooleanArray *onlyOnce = [IOSBooleanArray newArrayWithLength:n];
  for (jint i = 0; i < n; i++) {
    if ((IOSIntArray_Get(perm, i) < 0) || (IOSIntArray_Get(perm, i) >= n) || IOSBooleanArray_Get(onlyOnce, IOSIntArray_Get(perm, i))) {
      return false;
    }
    *IOSBooleanArray_GetRef(onlyOnce, IOSIntArray_Get(perm, i)) = true;
  }
  return true;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcMathLinearalgebraPermutation)