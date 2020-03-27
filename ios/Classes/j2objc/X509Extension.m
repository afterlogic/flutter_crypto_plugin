//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/X509Extension.java
//

#include "ASN1Boolean.h"
#include "ASN1Encodable.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "X509Extension.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1X509X509Extension)

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_subjectDirectoryAttributes;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_subjectKeyIdentifier;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_keyUsage;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_privateKeyUsagePeriod;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_subjectAlternativeName;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_issuerAlternativeName;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_basicConstraints;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_cRLNumber;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_reasonCode;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_instructionCode;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_invalidityDate;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_deltaCRLIndicator;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_issuingDistributionPoint;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_certificateIssuer;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_nameConstraints;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_cRLDistributionPoints;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_certificatePolicies;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_policyMappings;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_authorityKeyIdentifier;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_policyConstraints;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_extendedKeyUsage;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_freshestCRL;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_inhibitAnyPolicy;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_authorityInfoAccess;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_subjectInfoAccess;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_logoType;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_biometricInfo;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_qCStatements;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_auditIdentity;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_noRevAvail;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extension_targetInformation;

@implementation LibOrgBouncycastleAsn1X509X509Extension

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)subjectDirectoryAttributes {
  return LibOrgBouncycastleAsn1X509X509Extension_subjectDirectoryAttributes;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)subjectKeyIdentifier {
  return LibOrgBouncycastleAsn1X509X509Extension_subjectKeyIdentifier;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)keyUsage {
  return LibOrgBouncycastleAsn1X509X509Extension_keyUsage;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)privateKeyUsagePeriod {
  return LibOrgBouncycastleAsn1X509X509Extension_privateKeyUsagePeriod;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)subjectAlternativeName {
  return LibOrgBouncycastleAsn1X509X509Extension_subjectAlternativeName;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)issuerAlternativeName {
  return LibOrgBouncycastleAsn1X509X509Extension_issuerAlternativeName;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)basicConstraints {
  return LibOrgBouncycastleAsn1X509X509Extension_basicConstraints;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)cRLNumber {
  return LibOrgBouncycastleAsn1X509X509Extension_cRLNumber;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)reasonCode {
  return LibOrgBouncycastleAsn1X509X509Extension_reasonCode;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)instructionCode {
  return LibOrgBouncycastleAsn1X509X509Extension_instructionCode;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)invalidityDate {
  return LibOrgBouncycastleAsn1X509X509Extension_invalidityDate;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)deltaCRLIndicator {
  return LibOrgBouncycastleAsn1X509X509Extension_deltaCRLIndicator;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)issuingDistributionPoint {
  return LibOrgBouncycastleAsn1X509X509Extension_issuingDistributionPoint;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)certificateIssuer {
  return LibOrgBouncycastleAsn1X509X509Extension_certificateIssuer;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)nameConstraints {
  return LibOrgBouncycastleAsn1X509X509Extension_nameConstraints;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)cRLDistributionPoints {
  return LibOrgBouncycastleAsn1X509X509Extension_cRLDistributionPoints;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)certificatePolicies {
  return LibOrgBouncycastleAsn1X509X509Extension_certificatePolicies;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)policyMappings {
  return LibOrgBouncycastleAsn1X509X509Extension_policyMappings;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)authorityKeyIdentifier {
  return LibOrgBouncycastleAsn1X509X509Extension_authorityKeyIdentifier;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)policyConstraints {
  return LibOrgBouncycastleAsn1X509X509Extension_policyConstraints;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)extendedKeyUsage {
  return LibOrgBouncycastleAsn1X509X509Extension_extendedKeyUsage;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)freshestCRL {
  return LibOrgBouncycastleAsn1X509X509Extension_freshestCRL;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)inhibitAnyPolicy {
  return LibOrgBouncycastleAsn1X509X509Extension_inhibitAnyPolicy;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)authorityInfoAccess {
  return LibOrgBouncycastleAsn1X509X509Extension_authorityInfoAccess;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)subjectInfoAccess {
  return LibOrgBouncycastleAsn1X509X509Extension_subjectInfoAccess;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)logoType {
  return LibOrgBouncycastleAsn1X509X509Extension_logoType;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)biometricInfo {
  return LibOrgBouncycastleAsn1X509X509Extension_biometricInfo;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)qCStatements {
  return LibOrgBouncycastleAsn1X509X509Extension_qCStatements;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)auditIdentity {
  return LibOrgBouncycastleAsn1X509X509Extension_auditIdentity;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)noRevAvail {
  return LibOrgBouncycastleAsn1X509X509Extension_noRevAvail;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)targetInformation {
  return LibOrgBouncycastleAsn1X509X509Extension_targetInformation;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Boolean:(LibOrgBouncycastleAsn1ASN1Boolean *)critical
                withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)value {
  LibOrgBouncycastleAsn1X509X509Extension_initWithLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_(self, critical, value);
  return self;
}

- (instancetype)initWithBoolean:(jboolean)critical
withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)value {
  LibOrgBouncycastleAsn1X509X509Extension_initWithBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(self, critical, value);
  return self;
}

- (jboolean)isCritical {
  return critical_;
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getValue {
  return value_;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getParsedValue {
  return LibOrgBouncycastleAsn1X509X509Extension_convertValueToObjectWithLibOrgBouncycastleAsn1X509X509Extension_(self);
}

- (NSUInteger)hash {
  if ([self isCritical]) {
    return ((jint) [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk([self getValue])) hash]);
  }
  return ~((jint) [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk([self getValue])) hash]);
}

- (jboolean)isEqual:(id)o {
  if (!([o isKindOfClass:[LibOrgBouncycastleAsn1X509X509Extension class]])) {
    return false;
  }
  LibOrgBouncycastleAsn1X509X509Extension *other = (LibOrgBouncycastleAsn1X509X509Extension *) cast_chk(o, [LibOrgBouncycastleAsn1X509X509Extension class]);
  return [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk([((LibOrgBouncycastleAsn1X509X509Extension *) nil_chk(other)) getValue])) isEqual:[self getValue]] && ([other isCritical] == [self isCritical]);
}

+ (LibOrgBouncycastleAsn1ASN1Primitive *)convertValueToObjectWithLibOrgBouncycastleAsn1X509X509Extension:(LibOrgBouncycastleAsn1X509X509Extension *)ext {
  return LibOrgBouncycastleAsn1X509X509Extension_convertValueToObjectWithLibOrgBouncycastleAsn1X509X509Extension_(ext);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x9, 5, 6, 7, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Boolean:withLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[1].selector = @selector(initWithBoolean:withLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[2].selector = @selector(isCritical);
  methods[3].selector = @selector(getValue);
  methods[4].selector = @selector(getParsedValue);
  methods[5].selector = @selector(hash);
  methods[6].selector = @selector(isEqual:);
  methods[7].selector = @selector(convertValueToObjectWithLibOrgBouncycastleAsn1X509X509Extension:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "subjectDirectoryAttributes", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 8, -1, -1 },
    { "subjectKeyIdentifier", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 9, -1, -1 },
    { "keyUsage", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 10, -1, -1 },
    { "privateKeyUsagePeriod", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 11, -1, -1 },
    { "subjectAlternativeName", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 12, -1, -1 },
    { "issuerAlternativeName", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 13, -1, -1 },
    { "basicConstraints", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 14, -1, -1 },
    { "cRLNumber", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 15, -1, -1 },
    { "reasonCode", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 16, -1, -1 },
    { "instructionCode", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 17, -1, -1 },
    { "invalidityDate", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 18, -1, -1 },
    { "deltaCRLIndicator", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 19, -1, -1 },
    { "issuingDistributionPoint", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 20, -1, -1 },
    { "certificateIssuer", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 21, -1, -1 },
    { "nameConstraints", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 22, -1, -1 },
    { "cRLDistributionPoints", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 23, -1, -1 },
    { "certificatePolicies", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 24, -1, -1 },
    { "policyMappings", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 25, -1, -1 },
    { "authorityKeyIdentifier", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 26, -1, -1 },
    { "policyConstraints", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 27, -1, -1 },
    { "extendedKeyUsage", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 28, -1, -1 },
    { "freshestCRL", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 29, -1, -1 },
    { "inhibitAnyPolicy", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 30, -1, -1 },
    { "authorityInfoAccess", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 31, -1, -1 },
    { "subjectInfoAccess", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 32, -1, -1 },
    { "logoType", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 33, -1, -1 },
    { "biometricInfo", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 34, -1, -1 },
    { "qCStatements", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 35, -1, -1 },
    { "auditIdentity", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 36, -1, -1 },
    { "noRevAvail", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 37, -1, -1 },
    { "targetInformation", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 38, -1, -1 },
    { "critical_", "Z", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "value_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Boolean;LLibOrgBouncycastleAsn1ASN1OctetString;", "ZLLibOrgBouncycastleAsn1ASN1OctetString;", "hashCode", "equals", "LNSObject;", "convertValueToObject", "LLibOrgBouncycastleAsn1X509X509Extension;", "LJavaLangIllegalArgumentException;", &LibOrgBouncycastleAsn1X509X509Extension_subjectDirectoryAttributes, &LibOrgBouncycastleAsn1X509X509Extension_subjectKeyIdentifier, &LibOrgBouncycastleAsn1X509X509Extension_keyUsage, &LibOrgBouncycastleAsn1X509X509Extension_privateKeyUsagePeriod, &LibOrgBouncycastleAsn1X509X509Extension_subjectAlternativeName, &LibOrgBouncycastleAsn1X509X509Extension_issuerAlternativeName, &LibOrgBouncycastleAsn1X509X509Extension_basicConstraints, &LibOrgBouncycastleAsn1X509X509Extension_cRLNumber, &LibOrgBouncycastleAsn1X509X509Extension_reasonCode, &LibOrgBouncycastleAsn1X509X509Extension_instructionCode, &LibOrgBouncycastleAsn1X509X509Extension_invalidityDate, &LibOrgBouncycastleAsn1X509X509Extension_deltaCRLIndicator, &LibOrgBouncycastleAsn1X509X509Extension_issuingDistributionPoint, &LibOrgBouncycastleAsn1X509X509Extension_certificateIssuer, &LibOrgBouncycastleAsn1X509X509Extension_nameConstraints, &LibOrgBouncycastleAsn1X509X509Extension_cRLDistributionPoints, &LibOrgBouncycastleAsn1X509X509Extension_certificatePolicies, &LibOrgBouncycastleAsn1X509X509Extension_policyMappings, &LibOrgBouncycastleAsn1X509X509Extension_authorityKeyIdentifier, &LibOrgBouncycastleAsn1X509X509Extension_policyConstraints, &LibOrgBouncycastleAsn1X509X509Extension_extendedKeyUsage, &LibOrgBouncycastleAsn1X509X509Extension_freshestCRL, &LibOrgBouncycastleAsn1X509X509Extension_inhibitAnyPolicy, &LibOrgBouncycastleAsn1X509X509Extension_authorityInfoAccess, &LibOrgBouncycastleAsn1X509X509Extension_subjectInfoAccess, &LibOrgBouncycastleAsn1X509X509Extension_logoType, &LibOrgBouncycastleAsn1X509X509Extension_biometricInfo, &LibOrgBouncycastleAsn1X509X509Extension_qCStatements, &LibOrgBouncycastleAsn1X509X509Extension_auditIdentity, &LibOrgBouncycastleAsn1X509X509Extension_noRevAvail, &LibOrgBouncycastleAsn1X509X509Extension_targetInformation };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509X509Extension = { "X509Extension", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 8, 33, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509X509Extension;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1X509X509Extension class]) {
    LibOrgBouncycastleAsn1X509X509Extension_subjectDirectoryAttributes = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.9");
    LibOrgBouncycastleAsn1X509X509Extension_subjectKeyIdentifier = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.14");
    LibOrgBouncycastleAsn1X509X509Extension_keyUsage = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.15");
    LibOrgBouncycastleAsn1X509X509Extension_privateKeyUsagePeriod = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.16");
    LibOrgBouncycastleAsn1X509X509Extension_subjectAlternativeName = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.17");
    LibOrgBouncycastleAsn1X509X509Extension_issuerAlternativeName = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.18");
    LibOrgBouncycastleAsn1X509X509Extension_basicConstraints = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.19");
    LibOrgBouncycastleAsn1X509X509Extension_cRLNumber = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.20");
    LibOrgBouncycastleAsn1X509X509Extension_reasonCode = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.21");
    LibOrgBouncycastleAsn1X509X509Extension_instructionCode = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.23");
    LibOrgBouncycastleAsn1X509X509Extension_invalidityDate = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.24");
    LibOrgBouncycastleAsn1X509X509Extension_deltaCRLIndicator = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.27");
    LibOrgBouncycastleAsn1X509X509Extension_issuingDistributionPoint = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.28");
    LibOrgBouncycastleAsn1X509X509Extension_certificateIssuer = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.29");
    LibOrgBouncycastleAsn1X509X509Extension_nameConstraints = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.30");
    LibOrgBouncycastleAsn1X509X509Extension_cRLDistributionPoints = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.31");
    LibOrgBouncycastleAsn1X509X509Extension_certificatePolicies = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.32");
    LibOrgBouncycastleAsn1X509X509Extension_policyMappings = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.33");
    LibOrgBouncycastleAsn1X509X509Extension_authorityKeyIdentifier = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.35");
    LibOrgBouncycastleAsn1X509X509Extension_policyConstraints = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.36");
    LibOrgBouncycastleAsn1X509X509Extension_extendedKeyUsage = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.37");
    LibOrgBouncycastleAsn1X509X509Extension_freshestCRL = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.46");
    LibOrgBouncycastleAsn1X509X509Extension_inhibitAnyPolicy = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.54");
    LibOrgBouncycastleAsn1X509X509Extension_authorityInfoAccess = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.1");
    LibOrgBouncycastleAsn1X509X509Extension_subjectInfoAccess = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.11");
    LibOrgBouncycastleAsn1X509X509Extension_logoType = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.12");
    LibOrgBouncycastleAsn1X509X509Extension_biometricInfo = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.2");
    LibOrgBouncycastleAsn1X509X509Extension_qCStatements = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.3");
    LibOrgBouncycastleAsn1X509X509Extension_auditIdentity = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.4");
    LibOrgBouncycastleAsn1X509X509Extension_noRevAvail = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.56");
    LibOrgBouncycastleAsn1X509X509Extension_targetInformation = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.55");
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1X509X509Extension)
  }
}

@end

void LibOrgBouncycastleAsn1X509X509Extension_initWithLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1X509X509Extension *self, LibOrgBouncycastleAsn1ASN1Boolean *critical, LibOrgBouncycastleAsn1ASN1OctetString *value) {
  NSObject_init(self);
  self->critical_ = [((LibOrgBouncycastleAsn1ASN1Boolean *) nil_chk(critical)) isTrue];
  self->value_ = value;
}

LibOrgBouncycastleAsn1X509X509Extension *new_LibOrgBouncycastleAsn1X509X509Extension_initWithLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1Boolean *critical, LibOrgBouncycastleAsn1ASN1OctetString *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509X509Extension, initWithLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_, critical, value)
}

LibOrgBouncycastleAsn1X509X509Extension *create_LibOrgBouncycastleAsn1X509X509Extension_initWithLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1Boolean *critical, LibOrgBouncycastleAsn1ASN1OctetString *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509X509Extension, initWithLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_, critical, value)
}

void LibOrgBouncycastleAsn1X509X509Extension_initWithBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1X509X509Extension *self, jboolean critical, LibOrgBouncycastleAsn1ASN1OctetString *value) {
  NSObject_init(self);
  self->critical_ = critical;
  self->value_ = value;
}

LibOrgBouncycastleAsn1X509X509Extension *new_LibOrgBouncycastleAsn1X509X509Extension_initWithBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(jboolean critical, LibOrgBouncycastleAsn1ASN1OctetString *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509X509Extension, initWithBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_, critical, value)
}

LibOrgBouncycastleAsn1X509X509Extension *create_LibOrgBouncycastleAsn1X509X509Extension_initWithBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(jboolean critical, LibOrgBouncycastleAsn1ASN1OctetString *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509X509Extension, initWithBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_, critical, value)
}

LibOrgBouncycastleAsn1ASN1Primitive *LibOrgBouncycastleAsn1X509X509Extension_convertValueToObjectWithLibOrgBouncycastleAsn1X509X509Extension_(LibOrgBouncycastleAsn1X509X509Extension *ext) {
  LibOrgBouncycastleAsn1X509X509Extension_initialize();
  @try {
    return LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk([((LibOrgBouncycastleAsn1X509X509Extension *) nil_chk(ext)) getValue])) getOctets]);
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"can't convert extension: ", e));
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509X509Extension)
