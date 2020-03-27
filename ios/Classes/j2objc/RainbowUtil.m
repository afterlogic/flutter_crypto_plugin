//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/rainbow/util/RainbowUtil.java
//

#include "GF2Field.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "RainbowUtil.h"

@implementation LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (IOSIntArray *)convertArraytoIntWithByteArray:(IOSByteArray *)inArg {
  return LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArraytoIntWithByteArray_(inArg);
}

+ (IOSShortArray *)convertArrayWithByteArray:(IOSByteArray *)inArg {
  return LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArrayWithByteArray_(inArg);
}

+ (IOSObjectArray *)convertArrayWithByteArray2:(IOSObjectArray *)inArg {
  return LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArrayWithByteArray2_(inArg);
}

+ (IOSObjectArray *)convertArrayWithByteArray3:(IOSObjectArray *)inArg {
  return LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArrayWithByteArray3_(inArg);
}

+ (IOSByteArray *)convertIntArrayWithIntArray:(IOSIntArray *)inArg {
  return LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertIntArrayWithIntArray_(inArg);
}

+ (IOSByteArray *)convertArrayWithShortArray:(IOSShortArray *)inArg {
  return LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArrayWithShortArray_(inArg);
}

+ (IOSObjectArray *)convertArrayWithShortArray2:(IOSObjectArray *)inArg {
  return LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArrayWithShortArray2_(inArg);
}

+ (IOSObjectArray *)convertArrayWithShortArray3:(IOSObjectArray *)inArg {
  return LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArrayWithShortArray3_(inArg);
}

+ (jboolean)equalsWithShortArray:(IOSShortArray *)left
                  withShortArray:(IOSShortArray *)right {
  return LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_equalsWithShortArray_withShortArray_(left, right);
}

+ (jboolean)equalsWithShortArray2:(IOSObjectArray *)left
                  withShortArray2:(IOSObjectArray *)right {
  return LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_equalsWithShortArray2_withShortArray2_(left, right);
}

+ (jboolean)equalsWithShortArray3:(IOSObjectArray *)left
                  withShortArray3:(IOSObjectArray *)right {
  return LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_equalsWithShortArray3_withShortArray3_(left, right);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[I", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "[S", 0x9, 2, 1, -1, -1, -1, -1 },
    { NULL, "[[S", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "[[[S", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 2, 7, -1, -1, -1, -1 },
    { NULL, "[[B", 0x9, 2, 8, -1, -1, -1, -1 },
    { NULL, "[[[B", 0x9, 2, 9, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 10, 11, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 10, 12, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 10, 13, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(convertArraytoIntWithByteArray:);
  methods[2].selector = @selector(convertArrayWithByteArray:);
  methods[3].selector = @selector(convertArrayWithByteArray2:);
  methods[4].selector = @selector(convertArrayWithByteArray3:);
  methods[5].selector = @selector(convertIntArrayWithIntArray:);
  methods[6].selector = @selector(convertArrayWithShortArray:);
  methods[7].selector = @selector(convertArrayWithShortArray2:);
  methods[8].selector = @selector(convertArrayWithShortArray3:);
  methods[9].selector = @selector(equalsWithShortArray:withShortArray:);
  methods[10].selector = @selector(equalsWithShortArray2:withShortArray2:);
  methods[11].selector = @selector(equalsWithShortArray3:withShortArray3:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "convertArraytoInt", "[B", "convertArray", "[[B", "[[[B", "convertIntArray", "[I", "[S", "[[S", "[[[S", "equals", "[S[S", "[[S[[S", "[[[S[[[S" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil = { "RainbowUtil", "lib.org.bouncycastle.pqc.crypto.rainbow.util", ptrTable, methods, NULL, 7, 0x1, 12, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil;
}

@end

void LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_init(LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil *self) {
  NSObject_init(self);
}

LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil *new_LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil, init)
}

LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil *create_LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil, init)
}

IOSIntArray *LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArraytoIntWithByteArray_(IOSByteArray *inArg) {
  LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_initialize();
  IOSIntArray *out = [IOSIntArray newArrayWithLength:((IOSByteArray *) nil_chk(inArg))->size_];
  for (jint i = 0; i < inArg->size_; i++) {
    *IOSIntArray_GetRef(out, i) = IOSByteArray_Get(inArg, i) & LibOrgBouncycastlePqcCryptoRainbowUtilGF2Field_MASK;
  }
  return out;
}

IOSShortArray *LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArrayWithByteArray_(IOSByteArray *inArg) {
  LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_initialize();
  IOSShortArray *out = [IOSShortArray newArrayWithLength:((IOSByteArray *) nil_chk(inArg))->size_];
  for (jint i = 0; i < inArg->size_; i++) {
    *IOSShortArray_GetRef(out, i) = (jshort) (IOSByteArray_Get(inArg, i) & LibOrgBouncycastlePqcCryptoRainbowUtilGF2Field_MASK);
  }
  return out;
}

IOSObjectArray *LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArrayWithByteArray2_(IOSObjectArray *inArg) {
  LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_initialize();
  IOSObjectArray *out = [IOSShortArray newArrayWithDimensions:2 lengths:(jint[]){ ((IOSObjectArray *) nil_chk(inArg))->size_, ((IOSByteArray *) nil_chk(IOSObjectArray_Get(inArg, 0)))->size_ }];
  for (jint i = 0; i < inArg->size_; i++) {
    for (jint j = 0; j < ((IOSByteArray *) nil_chk(IOSObjectArray_Get(inArg, 0)))->size_; j++) {
      *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(out, i)), j) = (jshort) (IOSByteArray_Get(nil_chk(IOSObjectArray_Get(inArg, i)), j) & LibOrgBouncycastlePqcCryptoRainbowUtilGF2Field_MASK);
    }
  }
  return out;
}

IOSObjectArray *LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArrayWithByteArray3_(IOSObjectArray *inArg) {
  LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_initialize();
  IOSObjectArray *out = [IOSShortArray newArrayWithDimensions:3 lengths:(jint[]){ ((IOSObjectArray *) nil_chk(inArg))->size_, ((IOSObjectArray *) nil_chk(IOSObjectArray_Get(inArg, 0)))->size_, ((IOSByteArray *) nil_chk(IOSObjectArray_Get(nil_chk(IOSObjectArray_Get(inArg, 0)), 0)))->size_ }];
  for (jint i = 0; i < inArg->size_; i++) {
    for (jint j = 0; j < ((IOSObjectArray *) nil_chk(IOSObjectArray_Get(inArg, 0)))->size_; j++) {
      for (jint k = 0; k < ((IOSByteArray *) nil_chk(IOSObjectArray_Get(nil_chk(IOSObjectArray_Get(inArg, 0)), 0)))->size_; k++) {
        *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(nil_chk(IOSObjectArray_Get(out, i)), j)), k) = (jshort) (IOSByteArray_Get(nil_chk(IOSObjectArray_Get(nil_chk(IOSObjectArray_Get(inArg, i)), j)), k) & LibOrgBouncycastlePqcCryptoRainbowUtilGF2Field_MASK);
      }
    }
  }
  return out;
}

IOSByteArray *LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertIntArrayWithIntArray_(IOSIntArray *inArg) {
  LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_initialize();
  IOSByteArray *out = [IOSByteArray newArrayWithLength:((IOSIntArray *) nil_chk(inArg))->size_];
  for (jint i = 0; i < inArg->size_; i++) {
    *IOSByteArray_GetRef(out, i) = (jbyte) IOSIntArray_Get(inArg, i);
  }
  return out;
}

IOSByteArray *LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArrayWithShortArray_(IOSShortArray *inArg) {
  LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_initialize();
  IOSByteArray *out = [IOSByteArray newArrayWithLength:((IOSShortArray *) nil_chk(inArg))->size_];
  for (jint i = 0; i < inArg->size_; i++) {
    *IOSByteArray_GetRef(out, i) = (jbyte) IOSShortArray_Get(inArg, i);
  }
  return out;
}

IOSObjectArray *LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArrayWithShortArray2_(IOSObjectArray *inArg) {
  LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_initialize();
  IOSObjectArray *out = [IOSByteArray newArrayWithDimensions:2 lengths:(jint[]){ ((IOSObjectArray *) nil_chk(inArg))->size_, ((IOSShortArray *) nil_chk(IOSObjectArray_Get(inArg, 0)))->size_ }];
  for (jint i = 0; i < inArg->size_; i++) {
    for (jint j = 0; j < ((IOSShortArray *) nil_chk(IOSObjectArray_Get(inArg, 0)))->size_; j++) {
      *IOSByteArray_GetRef(nil_chk(IOSObjectArray_Get(out, i)), j) = (jbyte) IOSShortArray_Get(nil_chk(IOSObjectArray_Get(inArg, i)), j);
    }
  }
  return out;
}

IOSObjectArray *LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_convertArrayWithShortArray3_(IOSObjectArray *inArg) {
  LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_initialize();
  IOSObjectArray *out = [IOSByteArray newArrayWithDimensions:3 lengths:(jint[]){ ((IOSObjectArray *) nil_chk(inArg))->size_, ((IOSObjectArray *) nil_chk(IOSObjectArray_Get(inArg, 0)))->size_, ((IOSShortArray *) nil_chk(IOSObjectArray_Get(nil_chk(IOSObjectArray_Get(inArg, 0)), 0)))->size_ }];
  for (jint i = 0; i < inArg->size_; i++) {
    for (jint j = 0; j < ((IOSObjectArray *) nil_chk(IOSObjectArray_Get(inArg, 0)))->size_; j++) {
      for (jint k = 0; k < ((IOSShortArray *) nil_chk(IOSObjectArray_Get(nil_chk(IOSObjectArray_Get(inArg, 0)), 0)))->size_; k++) {
        *IOSByteArray_GetRef(nil_chk(IOSObjectArray_Get(nil_chk(IOSObjectArray_Get(out, i)), j)), k) = (jbyte) IOSShortArray_Get(nil_chk(IOSObjectArray_Get(nil_chk(IOSObjectArray_Get(inArg, i)), j)), k);
      }
    }
  }
  return out;
}

jboolean LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_equalsWithShortArray_withShortArray_(IOSShortArray *left, IOSShortArray *right) {
  LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_initialize();
  if (((IOSShortArray *) nil_chk(left))->size_ != ((IOSShortArray *) nil_chk(right))->size_) {
    return false;
  }
  jboolean result = true;
  for (jint i = left->size_ - 1; i >= 0; i--) {
    result &= (IOSShortArray_Get(left, i) == IOSShortArray_Get(right, i));
  }
  return result;
}

jboolean LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_equalsWithShortArray2_withShortArray2_(IOSObjectArray *left, IOSObjectArray *right) {
  LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_initialize();
  if (((IOSObjectArray *) nil_chk(left))->size_ != ((IOSObjectArray *) nil_chk(right))->size_) {
    return false;
  }
  jboolean result = true;
  for (jint i = left->size_ - 1; i >= 0; i--) {
    result &= LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_equalsWithShortArray_withShortArray_(IOSObjectArray_Get(left, i), IOSObjectArray_Get(right, i));
  }
  return result;
}

jboolean LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_equalsWithShortArray3_withShortArray3_(IOSObjectArray *left, IOSObjectArray *right) {
  LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_initialize();
  if (((IOSObjectArray *) nil_chk(left))->size_ != ((IOSObjectArray *) nil_chk(right))->size_) {
    return false;
  }
  jboolean result = true;
  for (jint i = left->size_ - 1; i >= 0; i--) {
    result &= LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil_equalsWithShortArray2_withShortArray2_(IOSObjectArray_Get(left, i), IOSObjectArray_Get(right, i));
  }
  return result;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoRainbowUtilRainbowUtil)
