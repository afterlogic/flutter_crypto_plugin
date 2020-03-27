//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/util/PrimeCertaintyCalculator.java
//

#include "J2ObjC_source.h"
#include "PrimeCertaintyCalculator.h"

@interface LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_init(LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator *self);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator *new_LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator *create_LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_init(void);

@implementation LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jint)getDefaultCertaintyWithInt:(jint)keySizeInBits {
  return LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_getDefaultCertaintyWithInt_(keySizeInBits);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getDefaultCertaintyWithInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "getDefaultCertainty", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator = { "PrimeCertaintyCalculator", "lib.org.bouncycastle.jcajce.provider.asymmetric.util", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_init(LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator *new_LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator *create_LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator, init)
}

jint LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_getDefaultCertaintyWithInt_(jint keySizeInBits) {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_initialize();
  return keySizeInBits <= 1024 ? 80 : (96 + 16 * ((keySizeInBits - 1) / 1024));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator)
