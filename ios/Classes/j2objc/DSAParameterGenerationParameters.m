//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/DSAParameterGenerationParameters.java
//

#include "DSAParameterGenerationParameters.h"
#include "J2ObjC_source.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters () {
 @public
  jint l_;
  jint n_;
  jint usageIndex_;
  jint certainty_;
  JavaSecuritySecureRandom *random_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters, random_, JavaSecuritySecureRandom *)

@implementation LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters

+ (jint)DIGITAL_SIGNATURE_USAGE {
  return LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters_DIGITAL_SIGNATURE_USAGE;
}

+ (jint)KEY_ESTABLISHMENT_USAGE {
  return LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters_KEY_ESTABLISHMENT_USAGE;
}

- (instancetype)initWithInt:(jint)L
                    withInt:(jint)N
                    withInt:(jint)certainty
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters_initWithInt_withInt_withInt_withJavaSecuritySecureRandom_(self, L, N, certainty, random);
  return self;
}

- (instancetype)initWithInt:(jint)L
                    withInt:(jint)N
                    withInt:(jint)certainty
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                    withInt:(jint)usageIndex {
  LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters_initWithInt_withInt_withInt_withJavaSecuritySecureRandom_withInt_(self, L, N, certainty, random, usageIndex);
  return self;
}

- (jint)getL {
  return l_;
}

- (jint)getN {
  return n_;
}

- (jint)getCertainty {
  return certainty_;
}

- (JavaSecuritySecureRandom *)getRandom {
  return random_;
}

- (jint)getUsageIndex {
  return usageIndex_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySecureRandom;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withInt:withInt:withJavaSecuritySecureRandom:);
  methods[1].selector = @selector(initWithInt:withInt:withInt:withJavaSecuritySecureRandom:withInt:);
  methods[2].selector = @selector(getL);
  methods[3].selector = @selector(getN);
  methods[4].selector = @selector(getCertainty);
  methods[5].selector = @selector(getRandom);
  methods[6].selector = @selector(getUsageIndex);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "DIGITAL_SIGNATURE_USAGE", "I", .constantValue.asInt = LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters_DIGITAL_SIGNATURE_USAGE, 0x19, -1, -1, -1, -1 },
    { "KEY_ESTABLISHMENT_USAGE", "I", .constantValue.asInt = LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters_KEY_ESTABLISHMENT_USAGE, 0x19, -1, -1, -1, -1 },
    { "l_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "n_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "usageIndex_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "certainty_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "IIILJavaSecuritySecureRandom;", "IIILJavaSecuritySecureRandom;I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters = { "DSAParameterGenerationParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 7, 7, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters;
}

@end

void LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters_initWithInt_withInt_withInt_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters *self, jint L, jint N, jint certainty, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters_initWithInt_withInt_withInt_withJavaSecuritySecureRandom_withInt_(self, L, N, certainty, random, -1);
}

LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters *new_LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters_initWithInt_withInt_withInt_withJavaSecuritySecureRandom_(jint L, jint N, jint certainty, JavaSecuritySecureRandom *random) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters, initWithInt_withInt_withInt_withJavaSecuritySecureRandom_, L, N, certainty, random)
}

LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters *create_LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters_initWithInt_withInt_withInt_withJavaSecuritySecureRandom_(jint L, jint N, jint certainty, JavaSecuritySecureRandom *random) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters, initWithInt_withInt_withInt_withJavaSecuritySecureRandom_, L, N, certainty, random)
}

void LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters_initWithInt_withInt_withInt_withJavaSecuritySecureRandom_withInt_(LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters *self, jint L, jint N, jint certainty, JavaSecuritySecureRandom *random, jint usageIndex) {
  NSObject_init(self);
  self->l_ = L;
  self->n_ = N;
  self->certainty_ = certainty;
  self->usageIndex_ = usageIndex;
  self->random_ = random;
}

LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters *new_LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters_initWithInt_withInt_withInt_withJavaSecuritySecureRandom_withInt_(jint L, jint N, jint certainty, JavaSecuritySecureRandom *random, jint usageIndex) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters, initWithInt_withInt_withInt_withJavaSecuritySecureRandom_withInt_, L, N, certainty, random, usageIndex)
}

LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters *create_LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters_initWithInt_withInt_withInt_withJavaSecuritySecureRandom_withInt_(jint L, jint N, jint certainty, JavaSecuritySecureRandom *random, jint usageIndex) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters, initWithInt_withInt_withInt_withJavaSecuritySecureRandom_withInt_, L, N, certainty, random, usageIndex)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters)
