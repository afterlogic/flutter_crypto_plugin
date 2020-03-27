//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/ParametersWithRandom.java
//

#include "CipherParameters.h"
#include "CryptoServicesRegistrar.h"
#include "J2ObjC_source.h"
#include "ParametersWithRandom.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoParamsParametersWithRandom () {
 @public
  JavaSecuritySecureRandom *random_;
  id<LibOrgBouncycastleCryptoCipherParameters> parameters_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsParametersWithRandom, random_, JavaSecuritySecureRandom *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsParametersWithRandom, parameters_, id<LibOrgBouncycastleCryptoCipherParameters>)

@implementation LibOrgBouncycastleCryptoParamsParametersWithRandom

- (instancetype)initWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters
                                    withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  LibOrgBouncycastleCryptoParamsParametersWithRandom_initWithLibOrgBouncycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(self, parameters, random);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters {
  LibOrgBouncycastleCryptoParamsParametersWithRandom_initWithLibOrgBouncycastleCryptoCipherParameters_(self, parameters);
  return self;
}

- (JavaSecuritySecureRandom *)getRandom {
  return random_;
}

- (id<LibOrgBouncycastleCryptoCipherParameters>)getParameters {
  return parameters_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySecureRandom;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoCipherParameters:withJavaSecuritySecureRandom:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getRandom);
  methods[3].selector = @selector(getParameters);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "parameters_", "LLibOrgBouncycastleCryptoCipherParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoCipherParameters;LJavaSecuritySecureRandom;", "LLibOrgBouncycastleCryptoCipherParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsParametersWithRandom = { "ParametersWithRandom", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 4, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsParametersWithRandom;
}

@end

void LibOrgBouncycastleCryptoParamsParametersWithRandom_initWithLibOrgBouncycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsParametersWithRandom *self, id<LibOrgBouncycastleCryptoCipherParameters> parameters, JavaSecuritySecureRandom *random) {
  NSObject_init(self);
  self->random_ = random;
  self->parameters_ = parameters;
}

LibOrgBouncycastleCryptoParamsParametersWithRandom *new_LibOrgBouncycastleCryptoParamsParametersWithRandom_initWithLibOrgBouncycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(id<LibOrgBouncycastleCryptoCipherParameters> parameters, JavaSecuritySecureRandom *random) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsParametersWithRandom, initWithLibOrgBouncycastleCryptoCipherParameters_withJavaSecuritySecureRandom_, parameters, random)
}

LibOrgBouncycastleCryptoParamsParametersWithRandom *create_LibOrgBouncycastleCryptoParamsParametersWithRandom_initWithLibOrgBouncycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(id<LibOrgBouncycastleCryptoCipherParameters> parameters, JavaSecuritySecureRandom *random) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsParametersWithRandom, initWithLibOrgBouncycastleCryptoCipherParameters_withJavaSecuritySecureRandom_, parameters, random)
}

void LibOrgBouncycastleCryptoParamsParametersWithRandom_initWithLibOrgBouncycastleCryptoCipherParameters_(LibOrgBouncycastleCryptoParamsParametersWithRandom *self, id<LibOrgBouncycastleCryptoCipherParameters> parameters) {
  LibOrgBouncycastleCryptoParamsParametersWithRandom_initWithLibOrgBouncycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(self, parameters, LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom());
}

LibOrgBouncycastleCryptoParamsParametersWithRandom *new_LibOrgBouncycastleCryptoParamsParametersWithRandom_initWithLibOrgBouncycastleCryptoCipherParameters_(id<LibOrgBouncycastleCryptoCipherParameters> parameters) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsParametersWithRandom, initWithLibOrgBouncycastleCryptoCipherParameters_, parameters)
}

LibOrgBouncycastleCryptoParamsParametersWithRandom *create_LibOrgBouncycastleCryptoParamsParametersWithRandom_initWithLibOrgBouncycastleCryptoCipherParameters_(id<LibOrgBouncycastleCryptoCipherParameters> parameters) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsParametersWithRandom, initWithLibOrgBouncycastleCryptoCipherParameters_, parameters)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsParametersWithRandom)
