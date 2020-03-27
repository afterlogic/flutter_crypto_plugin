//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/edec/EdECObjectIdentifiers.java
//

#include "ASN1ObjectIdentifier.h"
#include "EdECObjectIdentifiers.h"
#include "J2ObjC_source.h"

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers)

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_edwards_curve_algs;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_X25519;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_X448;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_Ed25519;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_Ed448;

@implementation LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)id_edwards_curve_algs {
  return LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_edwards_curve_algs;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)id_X25519 {
  return LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_X25519;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)id_X448 {
  return LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_X448;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)id_Ed25519 {
  return LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_Ed25519;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)id_Ed448 {
  return LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_Ed448;
}

+ (const J2ObjcClassInfo *)__metadata {
  static const J2ObjcFieldInfo fields[] = {
    { "id_edwards_curve_algs", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 0, -1, -1 },
    { "id_X25519", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 1, -1, -1 },
    { "id_X448", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 2, -1, -1 },
    { "id_Ed25519", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 3, -1, -1 },
    { "id_Ed448", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 4, -1, -1 },
  };
  static const void *ptrTable[] = { &LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_edwards_curve_algs, &LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_X25519, &LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_X448, &LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_Ed25519, &LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_Ed448 };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers = { "EdECObjectIdentifiers", "lib.org.bouncycastle.asn1.edec", ptrTable, NULL, fields, 7, 0x609, 0, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers class]) {
    LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_edwards_curve_algs = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.101");
    LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_X25519 = [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_edwards_curve_algs branchWithNSString:@"110"])) intern];
    LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_X448 = [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_edwards_curve_algs branchWithNSString:@"111"])) intern];
    LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_Ed25519 = [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_edwards_curve_algs branchWithNSString:@"112"])) intern];
    LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_Ed448 = [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers_id_edwards_curve_algs branchWithNSString:@"113"])) intern];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers)
  }
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers)
