//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/ECSecretBCPGKey.java
//

#include "BCPGInputStream.h"
#include "BCPGObject.h"
#include "BCPGOutputStream.h"
#include "ECSecretBCPGKey.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "MPInteger.h"
#include "java/io/IOException.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleBcpgECSecretBCPGKey

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg {
  LibOrgBouncycastleBcpgECSecretBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(self, inArg);
  return self;
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  LibOrgBouncycastleBcpgECSecretBCPGKey_initWithJavaMathBigInteger_(self, x);
  return self;
}

- (NSString *)getFormat {
  return @"PGP";
}

- (IOSByteArray *)getEncoded {
  @try {
    return [super getEncoded];
  }
  @catch (JavaIoIOException *e) {
    return nil;
  }
}

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg {
  [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(outArg)) writeObjectWithLibOrgBouncycastleBcpgBCPGObject:x_];
}

- (JavaMathBigInteger *)getX {
  return [((LibOrgBouncycastleBcpgMPInteger *) nil_chk(x_)) getValue];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, 1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[1].selector = @selector(initWithJavaMathBigInteger:);
  methods[2].selector = @selector(getFormat);
  methods[3].selector = @selector(getEncoded);
  methods[4].selector = @selector(encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:);
  methods[5].selector = @selector(getX);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "x_", "LLibOrgBouncycastleBcpgMPInteger;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleBcpgBCPGInputStream;", "LJavaIoIOException;", "LJavaMathBigInteger;", "encode", "LLibOrgBouncycastleBcpgBCPGOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgECSecretBCPGKey = { "ECSecretBCPGKey", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgECSecretBCPGKey;
}

@end

void LibOrgBouncycastleBcpgECSecretBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgECSecretBCPGKey *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  LibOrgBouncycastleBcpgBCPGObject_init(self);
  self->x_ = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
}

LibOrgBouncycastleBcpgECSecretBCPGKey *new_LibOrgBouncycastleBcpgECSecretBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgECSecretBCPGKey, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

LibOrgBouncycastleBcpgECSecretBCPGKey *create_LibOrgBouncycastleBcpgECSecretBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgECSecretBCPGKey, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

void LibOrgBouncycastleBcpgECSecretBCPGKey_initWithJavaMathBigInteger_(LibOrgBouncycastleBcpgECSecretBCPGKey *self, JavaMathBigInteger *x) {
  LibOrgBouncycastleBcpgBCPGObject_init(self);
  self->x_ = new_LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_(x);
}

LibOrgBouncycastleBcpgECSecretBCPGKey *new_LibOrgBouncycastleBcpgECSecretBCPGKey_initWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgECSecretBCPGKey, initWithJavaMathBigInteger_, x)
}

LibOrgBouncycastleBcpgECSecretBCPGKey *create_LibOrgBouncycastleBcpgECSecretBCPGKey_initWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgECSecretBCPGKey, initWithJavaMathBigInteger_, x)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgECSecretBCPGKey)