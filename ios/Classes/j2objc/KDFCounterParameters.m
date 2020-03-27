//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/KDFCounterParameters.java
//

#include "Arrays.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KDFCounterParameters.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleCryptoParamsKDFCounterParameters () {
 @public
  IOSByteArray *ki_;
  IOSByteArray *fixedInputDataCounterPrefix_;
  IOSByteArray *fixedInputDataCounterSuffix_;
  jint r_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsKDFCounterParameters, ki_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsKDFCounterParameters, fixedInputDataCounterPrefix_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsKDFCounterParameters, fixedInputDataCounterSuffix_, IOSByteArray *)

@implementation LibOrgBouncycastleCryptoParamsKDFCounterParameters

- (instancetype)initWithByteArray:(IOSByteArray *)ki
                    withByteArray:(IOSByteArray *)fixedInputDataCounterSuffix
                          withInt:(jint)r {
  LibOrgBouncycastleCryptoParamsKDFCounterParameters_initWithByteArray_withByteArray_withInt_(self, ki, fixedInputDataCounterSuffix, r);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)ki
                    withByteArray:(IOSByteArray *)fixedInputDataCounterPrefix
                    withByteArray:(IOSByteArray *)fixedInputDataCounterSuffix
                          withInt:(jint)r {
  LibOrgBouncycastleCryptoParamsKDFCounterParameters_initWithByteArray_withByteArray_withByteArray_withInt_(self, ki, fixedInputDataCounterPrefix, fixedInputDataCounterSuffix, r);
  return self;
}

- (IOSByteArray *)getKI {
  return ki_;
}

- (IOSByteArray *)getFixedInputData {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(fixedInputDataCounterSuffix_);
}

- (IOSByteArray *)getFixedInputDataCounterPrefix {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(fixedInputDataCounterPrefix_);
}

- (IOSByteArray *)getFixedInputDataCounterSuffix {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(fixedInputDataCounterSuffix_);
}

- (jint)getR {
  return r_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:withByteArray:withInt:);
  methods[1].selector = @selector(initWithByteArray:withByteArray:withByteArray:withInt:);
  methods[2].selector = @selector(getKI);
  methods[3].selector = @selector(getFixedInputData);
  methods[4].selector = @selector(getFixedInputDataCounterPrefix);
  methods[5].selector = @selector(getFixedInputDataCounterSuffix);
  methods[6].selector = @selector(getR);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ki_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "fixedInputDataCounterPrefix_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "fixedInputDataCounterSuffix_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "r_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[B[BI", "[B[B[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsKDFCounterParameters = { "KDFCounterParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x11, 7, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsKDFCounterParameters;
}

@end

void LibOrgBouncycastleCryptoParamsKDFCounterParameters_initWithByteArray_withByteArray_withInt_(LibOrgBouncycastleCryptoParamsKDFCounterParameters *self, IOSByteArray *ki, IOSByteArray *fixedInputDataCounterSuffix, jint r) {
  LibOrgBouncycastleCryptoParamsKDFCounterParameters_initWithByteArray_withByteArray_withByteArray_withInt_(self, ki, nil, fixedInputDataCounterSuffix, r);
}

LibOrgBouncycastleCryptoParamsKDFCounterParameters *new_LibOrgBouncycastleCryptoParamsKDFCounterParameters_initWithByteArray_withByteArray_withInt_(IOSByteArray *ki, IOSByteArray *fixedInputDataCounterSuffix, jint r) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsKDFCounterParameters, initWithByteArray_withByteArray_withInt_, ki, fixedInputDataCounterSuffix, r)
}

LibOrgBouncycastleCryptoParamsKDFCounterParameters *create_LibOrgBouncycastleCryptoParamsKDFCounterParameters_initWithByteArray_withByteArray_withInt_(IOSByteArray *ki, IOSByteArray *fixedInputDataCounterSuffix, jint r) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsKDFCounterParameters, initWithByteArray_withByteArray_withInt_, ki, fixedInputDataCounterSuffix, r)
}

void LibOrgBouncycastleCryptoParamsKDFCounterParameters_initWithByteArray_withByteArray_withByteArray_withInt_(LibOrgBouncycastleCryptoParamsKDFCounterParameters *self, IOSByteArray *ki, IOSByteArray *fixedInputDataCounterPrefix, IOSByteArray *fixedInputDataCounterSuffix, jint r) {
  NSObject_init(self);
  if (ki == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"A KDF requires Ki (a seed) as input");
  }
  self->ki_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(ki);
  if (fixedInputDataCounterPrefix == nil) {
    self->fixedInputDataCounterPrefix_ = [IOSByteArray newArrayWithLength:0];
  }
  else {
    self->fixedInputDataCounterPrefix_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(fixedInputDataCounterPrefix);
  }
  if (fixedInputDataCounterSuffix == nil) {
    self->fixedInputDataCounterSuffix_ = [IOSByteArray newArrayWithLength:0];
  }
  else {
    self->fixedInputDataCounterSuffix_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(fixedInputDataCounterSuffix);
  }
  if (r != 8 && r != 16 && r != 24 && r != 32) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Length of counter should be 8, 16, 24 or 32");
  }
  self->r_ = r;
}

LibOrgBouncycastleCryptoParamsKDFCounterParameters *new_LibOrgBouncycastleCryptoParamsKDFCounterParameters_initWithByteArray_withByteArray_withByteArray_withInt_(IOSByteArray *ki, IOSByteArray *fixedInputDataCounterPrefix, IOSByteArray *fixedInputDataCounterSuffix, jint r) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsKDFCounterParameters, initWithByteArray_withByteArray_withByteArray_withInt_, ki, fixedInputDataCounterPrefix, fixedInputDataCounterSuffix, r)
}

LibOrgBouncycastleCryptoParamsKDFCounterParameters *create_LibOrgBouncycastleCryptoParamsKDFCounterParameters_initWithByteArray_withByteArray_withByteArray_withInt_(IOSByteArray *ki, IOSByteArray *fixedInputDataCounterPrefix, IOSByteArray *fixedInputDataCounterSuffix, jint r) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsKDFCounterParameters, initWithByteArray_withByteArray_withByteArray_withInt_, ki, fixedInputDataCounterPrefix, fixedInputDataCounterSuffix, r)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsKDFCounterParameters)
