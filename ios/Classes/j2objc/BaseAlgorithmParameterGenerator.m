//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/util/BaseAlgorithmParameterGenerator.java
//

#include "BCJcaJceHelper.h"
#include "BaseAlgorithmParameterGenerator.h"
#include "J2ObjC_source.h"
#include "JcaJceHelper.h"
#include "java/security/AlgorithmParameterGeneratorSpi.h"
#include "java/security/AlgorithmParameters.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator () {
 @public
  id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator, helper_, id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)

@implementation LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (JavaSecurityAlgorithmParameters *)createParametersInstanceWithNSString:(NSString *)algorithm {
  return [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(helper_)) createAlgorithmParametersWithNSString:algorithm];
}

- (void)engineInitWithInt:(jint)strength
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  self->strength_ = strength;
  self->random_ = random;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityAlgorithmParameters;", 0x14, 0, 1, 2, -1, -1, -1 },
    { NULL, "V", 0x4, 3, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(createParametersInstanceWithNSString:);
  methods[2].selector = @selector(engineInitWithInt:withJavaSecuritySecureRandom:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "helper_", "LLibOrgBouncycastleJcajceUtilJcaJceHelper;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "strength_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "createParametersInstance", "LNSString;", "LJavaSecurityNoSuchAlgorithmException;LJavaSecurityNoSuchProviderException;", "engineInit", "ILJavaSecuritySecureRandom;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator = { "BaseAlgorithmParameterGenerator", "lib.org.bouncycastle.jcajce.provider.symmetric.util", ptrTable, methods, fields, 7, 0x401, 3, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator_init(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator *self) {
  JavaSecurityAlgorithmParameterGeneratorSpi_init(self);
  self->helper_ = new_LibOrgBouncycastleJcajceUtilBCJcaJceHelper_init();
  self->strength_ = 1024;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator)
