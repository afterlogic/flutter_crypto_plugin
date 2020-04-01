//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/microsoft/MicrosoftObjectIdentifiers.java
//

#include "ASN1ObjectIdentifier.h"
#include "J2ObjC_source.h"
#include "MicrosoftObjectIdentifiers.h"

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers)

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV1;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCaVersion;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftPrevCaCertHash;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCrlNextPublish;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV2;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftAppPolicies;

@implementation LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)microsoft {
  return LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)microsoftCertTemplateV1 {
  return LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV1;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)microsoftCaVersion {
  return LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCaVersion;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)microsoftPrevCaCertHash {
  return LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftPrevCaCertHash;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)microsoftCrlNextPublish {
  return LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCrlNextPublish;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)microsoftCertTemplateV2 {
  return LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV2;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)microsoftAppPolicies {
  return LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftAppPolicies;
}

+ (const J2ObjcClassInfo *)__metadata {
  static const J2ObjcFieldInfo fields[] = {
    { "microsoft", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 0, -1, -1 },
    { "microsoftCertTemplateV1", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 1, -1, -1 },
    { "microsoftCaVersion", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 2, -1, -1 },
    { "microsoftPrevCaCertHash", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 3, -1, -1 },
    { "microsoftCrlNextPublish", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 4, -1, -1 },
    { "microsoftCertTemplateV2", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 5, -1, -1 },
    { "microsoftAppPolicies", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 6, -1, -1 },
  };
  static const void *ptrTable[] = { &LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft, &LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV1, &LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCaVersion, &LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftPrevCaCertHash, &LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCrlNextPublish, &LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV2, &LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftAppPolicies };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers = { "MicrosoftObjectIdentifiers", "lib.org.bouncycastle.asn1.microsoft", ptrTable, NULL, fields, 7, 0x609, 0, 7, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers class]) {
    LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.4.1.311");
    LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV1 = [LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft branchWithNSString:@"20.2"];
    LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCaVersion = [LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft branchWithNSString:@"21.1"];
    LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftPrevCaCertHash = [LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft branchWithNSString:@"21.2"];
    LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCrlNextPublish = [LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft branchWithNSString:@"21.4"];
    LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV2 = [LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft branchWithNSString:@"21.7"];
    LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftAppPolicies = [LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft branchWithNSString:@"21.10"];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers)
  }
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1MicrosoftMicrosoftObjectIdentifiers)