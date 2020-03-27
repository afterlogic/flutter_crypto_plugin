//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/MPInteger.java
//

#include "BCPGInputStream.h"
#include "BCPGObject.h"
#include "BCPGOutputStream.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "MPInteger.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleBcpgMPInteger

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg {
  LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(self, inArg);
  return self;
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)value {
  LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_(self, value);
  return self;
}

- (JavaMathBigInteger *)getValue {
  return value_;
}

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg {
  jint length = [((JavaMathBigInteger *) nil_chk(value_)) bitLength];
  [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(outArg)) writeWithInt:JreRShift32(length, 8)];
  [outArg writeWithInt:length];
  IOSByteArray *bytes = [((JavaMathBigInteger *) nil_chk(value_)) toByteArray];
  if (IOSByteArray_Get(nil_chk(bytes), 0) == 0) {
    [outArg writeWithByteArray:bytes withInt:1 withInt:bytes->size_ - 1];
  }
  else {
    [outArg writeWithByteArray:bytes withInt:0 withInt:bytes->size_];
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[1].selector = @selector(initWithJavaMathBigInteger:);
  methods[2].selector = @selector(getValue);
  methods[3].selector = @selector(encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "value_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleBcpgBCPGInputStream;", "LJavaIoIOException;", "LJavaMathBigInteger;", "encode", "LLibOrgBouncycastleBcpgBCPGOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgMPInteger = { "MPInteger", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgMPInteger;
}

@end

void LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgMPInteger *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  LibOrgBouncycastleBcpgBCPGObject_init(self);
  self->value_ = nil;
  jint length = (JreLShift32([((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(inArg)) read], 8)) | [inArg read];
  IOSByteArray *bytes = [IOSByteArray newArrayWithLength:(length + 7) / 8];
  [inArg readFullyWithByteArray:bytes];
  self->value_ = new_JavaMathBigInteger_initWithInt_withByteArray_(1, bytes);
}

LibOrgBouncycastleBcpgMPInteger *new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgMPInteger, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

LibOrgBouncycastleBcpgMPInteger *create_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgMPInteger, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

void LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_(LibOrgBouncycastleBcpgMPInteger *self, JavaMathBigInteger *value) {
  LibOrgBouncycastleBcpgBCPGObject_init(self);
  self->value_ = nil;
  if (value == nil || [value signum] < 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"value must not be null, or negative");
  }
  self->value_ = value;
}

LibOrgBouncycastleBcpgMPInteger *new_LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_(JavaMathBigInteger *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgMPInteger, initWithJavaMathBigInteger_, value)
}

LibOrgBouncycastleBcpgMPInteger *create_LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_(JavaMathBigInteger *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgMPInteger, initWithJavaMathBigInteger_, value)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgMPInteger)
