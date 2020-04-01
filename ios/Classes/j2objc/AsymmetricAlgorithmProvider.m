//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/util/AsymmetricAlgorithmProvider.java
//

#include "ASN1ObjectIdentifier.h"
#include "AlgorithmProvider.h"
#include "AsymmetricAlgorithmProvider.h"
#include "AsymmetricKeyInfoConverter.h"
#include "ConfigurableProvider.h"
#include "J2ObjC_source.h"

@implementation LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider
                                                                               withNSString:(NSString *)algorithm
                                                                               withNSString:(NSString *)className_
                                             withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:JreStrcat("$$", @"Signature.", algorithm) withNSString:className_];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.Signature.", oid) withNSString:algorithm];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.Signature.OID.", oid) withNSString:algorithm];
}

- (void)addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider
                                                                               withNSString:(NSString *)digest
                                                                               withNSString:(NSString *)algorithm
                                                                               withNSString:(NSString *)className_
                                             withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid {
  NSString *mainName = JreStrcat("$$$", digest, @"WITH", algorithm);
  NSString *jdk11Variation1 = JreStrcat("$$$", digest, @"with", algorithm);
  NSString *jdk11Variation2 = JreStrcat("$$$", digest, @"With", algorithm);
  NSString *alias = JreStrcat("$C$", digest, '/', algorithm);
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:JreStrcat("$$", @"Signature.", mainName) withNSString:className_];
  [provider addAlgorithmWithNSString:JreStrcat("$$", @"Alg.Alias.Signature.", jdk11Variation1) withNSString:mainName];
  [provider addAlgorithmWithNSString:JreStrcat("$$", @"Alg.Alias.Signature.", jdk11Variation2) withNSString:mainName];
  [provider addAlgorithmWithNSString:JreStrcat("$$", @"Alg.Alias.Signature.", alias) withNSString:mainName];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.Signature.", oid) withNSString:mainName];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.Signature.OID.", oid) withNSString:mainName];
}

- (void)registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider
                                   withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                                                     withNSString:(NSString *)name
               withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:(id<LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter>)keyFactory {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.KeyFactory.", oid) withNSString:name];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.KeyPairGenerator.", oid) withNSString:name];
  [provider addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:oid withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:keyFactory];
}

- (void)registerOidAlgorithmParametersWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider
                                                      withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                                                                        withNSString:(NSString *)name {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.AlgorithmParameters.", oid) withNSString:name];
}

- (void)registerOidAlgorithmParameterGeneratorWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider
                                                              withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                                                                                withNSString:(NSString *)name {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.AlgorithmParameterGenerator.", oid) withNSString:name];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.AlgorithmParameters.", oid) withNSString:name];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 0, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 3, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 7, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:withNSString:withNSString:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[2].selector = @selector(addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:withNSString:withNSString:withNSString:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[3].selector = @selector(registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withNSString:withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:);
  methods[4].selector = @selector(registerOidAlgorithmParametersWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withNSString:);
  methods[5].selector = @selector(registerOidAlgorithmParameterGeneratorWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withNSString:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "addSignatureAlgorithm", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;LNSString;LNSString;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;LNSString;LNSString;LNSString;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "registerOid", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LNSString;LLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter;", "registerOidAlgorithmParameters", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LNSString;", "registerOidAlgorithmParameterGenerator" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider = { "AsymmetricAlgorithmProvider", "lib.org.bouncycastle.jcajce.provider.util", ptrTable, methods, NULL, 7, 0x401, 6, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider;
}

@end

void LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider_init(LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider *self) {
  LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider_init(self);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider)