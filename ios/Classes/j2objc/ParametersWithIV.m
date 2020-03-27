//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/ParametersWithIV.java
//

#include "CipherParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ParametersWithIV.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoParamsParametersWithIV () {
 @public
  IOSByteArray *iv_;
  id<LibOrgBouncycastleCryptoCipherParameters> parameters_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsParametersWithIV, iv_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsParametersWithIV, parameters_, id<LibOrgBouncycastleCryptoCipherParameters>)

@implementation LibOrgBouncycastleCryptoParamsParametersWithIV

- (instancetype)initWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters
                                                   withByteArray:(IOSByteArray *)iv {
  LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(self, parameters, iv);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters
                                                   withByteArray:(IOSByteArray *)iv
                                                         withInt:(jint)ivOff
                                                         withInt:(jint)ivLen {
  LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_withInt_withInt_(self, parameters, iv, ivOff, ivLen);
  return self;
}

- (IOSByteArray *)getIV {
  return iv_;
}

- (id<LibOrgBouncycastleCryptoCipherParameters>)getParameters {
  return parameters_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoCipherParameters:withByteArray:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoCipherParameters:withByteArray:withInt:withInt:);
  methods[2].selector = @selector(getIV);
  methods[3].selector = @selector(getParameters);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "iv_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "parameters_", "LLibOrgBouncycastleCryptoCipherParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoCipherParameters;[B", "LLibOrgBouncycastleCryptoCipherParameters;[BII" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsParametersWithIV = { "ParametersWithIV", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 4, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsParametersWithIV;
}

@end

void LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(LibOrgBouncycastleCryptoParamsParametersWithIV *self, id<LibOrgBouncycastleCryptoCipherParameters> parameters, IOSByteArray *iv) {
  LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_withInt_withInt_(self, parameters, iv, 0, ((IOSByteArray *) nil_chk(iv))->size_);
}

LibOrgBouncycastleCryptoParamsParametersWithIV *new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(id<LibOrgBouncycastleCryptoCipherParameters> parameters, IOSByteArray *iv) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsParametersWithIV, initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_, parameters, iv)
}

LibOrgBouncycastleCryptoParamsParametersWithIV *create_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(id<LibOrgBouncycastleCryptoCipherParameters> parameters, IOSByteArray *iv) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsParametersWithIV, initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_, parameters, iv)
}

void LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_withInt_withInt_(LibOrgBouncycastleCryptoParamsParametersWithIV *self, id<LibOrgBouncycastleCryptoCipherParameters> parameters, IOSByteArray *iv, jint ivOff, jint ivLen) {
  NSObject_init(self);
  self->iv_ = [IOSByteArray newArrayWithLength:ivLen];
  self->parameters_ = parameters;
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(iv, ivOff, self->iv_, 0, ivLen);
}

LibOrgBouncycastleCryptoParamsParametersWithIV *new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_withInt_withInt_(id<LibOrgBouncycastleCryptoCipherParameters> parameters, IOSByteArray *iv, jint ivOff, jint ivLen) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsParametersWithIV, initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_withInt_withInt_, parameters, iv, ivOff, ivLen)
}

LibOrgBouncycastleCryptoParamsParametersWithIV *create_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_withInt_withInt_(id<LibOrgBouncycastleCryptoCipherParameters> parameters, IOSByteArray *iv, jint ivOff, jint ivLen) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsParametersWithIV, initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_withInt_withInt_, parameters, iv, ivOff, ivLen)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsParametersWithIV)
