//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/ECGOST.java
//

#include "ASN1ObjectIdentifier.h"
#include "AsymmetricAlgorithmProvider.h"
#include "ConfigurableProvider.h"
#include "CryptoProObjectIdentifiers.h"
#include "ECGOST.h"
#include "J2ObjC_source.h"
#include "JcajceEcgost12KeyFactorySpi.h"
#include "JcajceEcgostKeyFactorySpi.h"
#include "RosstandartObjectIdentifiers.h"

inline NSString *LibOrgBouncycastleJcajceProviderAsymmetricECGOST_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX = @"lib.org.bouncycastle.jcajce.provider.asymmetric.ecgost.";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricECGOST, PREFIX, NSString *)

inline NSString *LibOrgBouncycastleJcajceProviderAsymmetricECGOST_get_PREFIX_GOST_2012(void);
static NSString *LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX_GOST_2012 = @"lib.org.bouncycastle.jcajce.provider.asymmetric.ecgost12.";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricECGOST, PREFIX_GOST_2012, NSString *)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricECGOST

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricECGOST_init(self);
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
  static const J2ObjcFieldInfo fields[] = {
    { "PREFIX", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 0, -1, -1 },
    { "PREFIX_GOST_2012", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 1, -1, -1 },
  };
  static const void *ptrTable[] = { &LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX, &LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX_GOST_2012, "LLibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricECGOST = { "ECGOST", "lib.org.bouncycastle.jcajce.provider.asymmetric", ptrTable, methods, fields, 7, 0x1, 1, 2, -1, 2, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricECGOST;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricECGOST_init(LibOrgBouncycastleJcajceProviderAsymmetricECGOST *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricECGOST *new_LibOrgBouncycastleJcajceProviderAsymmetricECGOST_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricECGOST, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricECGOST *create_LibOrgBouncycastleJcajceProviderAsymmetricECGOST_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricECGOST, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricECGOST)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"KeyFactory.ECGOST3410" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX, @"JcajceEcgostKeyFactorySpi")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyFactory.GOST-3410-2001" withNSString:@"ECGOST3410"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyFactory.ECGOST-3410" withNSString:@"ECGOST3410"];
  [self registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001) withNSString:@"ECGOST3410" withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyFactorySpi_init()];
  [self registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001DH) withNSString:@"ECGOST3410" withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyFactorySpi_init()];
  [self registerOidAlgorithmParametersWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001) withNSString:@"ECGOST3410"];
  [provider addAlgorithmWithNSString:@"KeyPairGenerator.ECGOST3410" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX, @"JcajceEcgostKeyPairGeneratorSpi")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyPairGenerator.ECGOST-3410" withNSString:@"ECGOST3410"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyPairGenerator.GOST-3410-2001" withNSString:@"ECGOST3410"];
  [provider addAlgorithmWithNSString:@"Signature.ECGOST3410" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX, @"JcajceEcgostSignatureSpi")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.ECGOST-3410" withNSString:@"ECGOST3410"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.GOST-3410-2001" withNSString:@"ECGOST3410"];
  [provider addAlgorithmWithNSString:@"KeyAgreement.ECGOST3410" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX, @"JcajceEcgostKeyAgreementSpi$ECVKO")];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.KeyAgreement.", JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001)) withNSString:@"ECGOST3410"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyAgreement.GOST-3410-2001" withNSString:@"ECGOST3410"];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.KeyAgreement.", JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_ESDH)) withNSString:@"ECGOST3410"];
  [provider addAlgorithmWithNSString:@"AlgorithmParameters.ECGOST3410" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX, @"AlgorithmParametersSpi")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.AlgorithmParameters.GOST-3410-2001" withNSString:@"ECGOST3410"];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"GOST3411" withNSString:@"ECGOST3410" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX, @"JcajceEcgostSignatureSpi") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3411_94_with_gostR3410_2001)];
  [provider addAlgorithmWithNSString:@"KeyFactory.ECGOST3410-2012" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX_GOST_2012, @"JcajceEcgostKeyFactorySpi")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyFactory.GOST-3410-2012" withNSString:@"ECGOST3410-2012"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyFactory.ECGOST-3410-2012" withNSString:@"ECGOST3410-2012"];
  [self registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_256) withNSString:@"ECGOST3410-2012" withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyFactorySpi_init()];
  [self registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_agreement_gost_3410_12_256) withNSString:@"ECGOST3410-2012" withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyFactorySpi_init()];
  [self registerOidAlgorithmParametersWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_256) withNSString:@"ECGOST3410-2012"];
  [self registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_512) withNSString:@"ECGOST3410-2012" withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyFactorySpi_init()];
  [self registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_agreement_gost_3410_12_512) withNSString:@"ECGOST3410-2012" withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyFactorySpi_init()];
  [self registerOidAlgorithmParametersWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_512) withNSString:@"ECGOST3410-2012"];
  [provider addAlgorithmWithNSString:@"KeyPairGenerator.ECGOST3410-2012" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX_GOST_2012, @"JcajceEcgostKeyPairGeneratorSpi")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyPairGenerator.ECGOST3410-2012" withNSString:@"ECGOST3410-2012"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyPairGenerator.GOST-3410-2012" withNSString:@"ECGOST3410-2012"];
  [provider addAlgorithmWithNSString:@"Signature.ECGOST3410-2012-256" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX_GOST_2012, @"ECGOST2012SignatureSpi256")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.ECGOST3410-2012-256" withNSString:@"ECGOST3410-2012-256"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.GOST-3410-2012-256" withNSString:@"ECGOST3410-2012-256"];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"GOST3411-2012-256" withNSString:@"ECGOST3410-2012-256" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX_GOST_2012, @"ECGOST2012SignatureSpi256") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_signwithdigest_gost_3410_12_256)];
  [provider addAlgorithmWithNSString:@"Signature.ECGOST3410-2012-512" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX_GOST_2012, @"ECGOST2012SignatureSpi512")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.ECGOST3410-2012-512" withNSString:@"ECGOST3410-2012-512"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.GOST-3410-2012-512" withNSString:@"ECGOST3410-2012-512"];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"GOST3411-2012-512" withNSString:@"ECGOST3410-2012-512" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX_GOST_2012, @"ECGOST2012SignatureSpi512") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_signwithdigest_gost_3410_12_512)];
  [provider addAlgorithmWithNSString:@"KeyAgreement.ECGOST3410-2012-256" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX_GOST_2012, @"JcajceEcgostKeyAgreementSpi$ECVKO256")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.ECGOST3410-2012-512" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricECGOST_PREFIX_GOST_2012, @"JcajceEcgostKeyAgreementSpi$ECVKO512")];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.KeyAgreement.", JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_agreement_gost_3410_12_256)) withNSString:@"ECGOST3410-2012-256"];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.KeyAgreement.", JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_agreement_gost_3410_12_512)) withNSString:@"ECGOST3410-2012-512"];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.KeyAgreement.", JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_256)) withNSString:@"ECGOST3410-2012-256"];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.KeyAgreement.", JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_512)) withNSString:@"ECGOST3410-2012-512"];
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
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", "LLibOrgBouncycastleJcajceProviderAsymmetricECGOST;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.asymmetric", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings_init(LibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings *new_LibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings *create_LibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricECGOST_Mappings)
