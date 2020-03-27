//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/DHValidationParameters.java
//

#include "Arrays.h"
#include "DHValidationParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleCryptoParamsDHValidationParameters () {
 @public
  IOSByteArray *seed_;
  jint counter_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsDHValidationParameters, seed_, IOSByteArray *)

@implementation LibOrgBouncycastleCryptoParamsDHValidationParameters

- (instancetype)initWithByteArray:(IOSByteArray *)seed
                          withInt:(jint)counter {
  LibOrgBouncycastleCryptoParamsDHValidationParameters_initWithByteArray_withInt_(self, seed, counter);
  return self;
}

- (jint)getCounter {
  return counter_;
}

- (IOSByteArray *)getSeed {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(seed_);
}

- (jboolean)isEqual:(id)o {
  if (!([o isKindOfClass:[LibOrgBouncycastleCryptoParamsDHValidationParameters class]])) {
    return false;
  }
  LibOrgBouncycastleCryptoParamsDHValidationParameters *other = (LibOrgBouncycastleCryptoParamsDHValidationParameters *) cast_chk(o, [LibOrgBouncycastleCryptoParamsDHValidationParameters class]);
  if (((LibOrgBouncycastleCryptoParamsDHValidationParameters *) nil_chk(other))->counter_ != self->counter_) {
    return false;
  }
  return LibOrgBouncycastleUtilArrays_areEqualWithByteArray_withByteArray_(self->seed_, other->seed_);
}

- (NSUInteger)hash {
  return counter_ ^ LibOrgBouncycastleUtilArrays_hashCodeWithByteArray_(seed_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:withInt:);
  methods[1].selector = @selector(getCounter);
  methods[2].selector = @selector(getSeed);
  methods[3].selector = @selector(isEqual:);
  methods[4].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "seed_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "counter_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[BI", "equals", "LNSObject;", "hashCode" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsDHValidationParameters = { "DHValidationParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsDHValidationParameters;
}

@end

void LibOrgBouncycastleCryptoParamsDHValidationParameters_initWithByteArray_withInt_(LibOrgBouncycastleCryptoParamsDHValidationParameters *self, IOSByteArray *seed, jint counter) {
  NSObject_init(self);
  self->seed_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(seed);
  self->counter_ = counter;
}

LibOrgBouncycastleCryptoParamsDHValidationParameters *new_LibOrgBouncycastleCryptoParamsDHValidationParameters_initWithByteArray_withInt_(IOSByteArray *seed, jint counter) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsDHValidationParameters, initWithByteArray_withInt_, seed, counter)
}

LibOrgBouncycastleCryptoParamsDHValidationParameters *create_LibOrgBouncycastleCryptoParamsDHValidationParameters_initWithByteArray_withInt_(IOSByteArray *seed, jint counter) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsDHValidationParameters, initWithByteArray_withInt_, seed, counter)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsDHValidationParameters)
