//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/X509.java
//

#include "AsymmetricAlgorithmProvider.h"
#include "ConfigurableProvider.h"
#include "J2ObjC_source.h"
#include "X509.h"

@implementation LibOrgBouncycastleJcajceProviderAsymmetricX509

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricX509_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricX509 = { "X509", "lib.org.bouncycastle.jcajce.provider.asymmetric", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricX509;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricX509_init(LibOrgBouncycastleJcajceProviderAsymmetricX509 *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricX509 *new_LibOrgBouncycastleJcajceProviderAsymmetricX509_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricX509 *create_LibOrgBouncycastleJcajceProviderAsymmetricX509_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricX509)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"KeyFactory.X.509" withNSString:@"lib.org.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyFactory.X509" withNSString:@"X.509"];
  [provider addAlgorithmWithNSString:@"CertificateFactory.X.509" withNSString:@"lib.org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.CertificateFactory.X509" withNSString:@"X.509"];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", "LLibOrgBouncycastleJcajceProviderAsymmetricX509;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.asymmetric", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings_init(LibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings *new_LibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings *create_LibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricX509_Mappings)