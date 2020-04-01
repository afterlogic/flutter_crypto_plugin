//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/Extension.java
//

#ifndef Extension_H
#define Extension_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1Boolean;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1OctetString;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1X509Extension : LibOrgBouncycastleAsn1ASN1Object
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *subjectDirectoryAttributes NS_SWIFT_NAME(subjectDirectoryAttributes);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *subjectKeyIdentifier NS_SWIFT_NAME(subjectKeyIdentifier);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *keyUsage NS_SWIFT_NAME(keyUsage);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *privateKeyUsagePeriod NS_SWIFT_NAME(privateKeyUsagePeriod);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *subjectAlternativeName NS_SWIFT_NAME(subjectAlternativeName);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *issuerAlternativeName NS_SWIFT_NAME(issuerAlternativeName);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *basicConstraints NS_SWIFT_NAME(basicConstraints);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *cRLNumber NS_SWIFT_NAME(cRLNumber);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *reasonCode NS_SWIFT_NAME(reasonCode);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *instructionCode NS_SWIFT_NAME(instructionCode);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *invalidityDate NS_SWIFT_NAME(invalidityDate);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *deltaCRLIndicator NS_SWIFT_NAME(deltaCRLIndicator);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *issuingDistributionPoint NS_SWIFT_NAME(issuingDistributionPoint);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *certificateIssuer NS_SWIFT_NAME(certificateIssuer);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *nameConstraints NS_SWIFT_NAME(nameConstraints);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *cRLDistributionPoints NS_SWIFT_NAME(cRLDistributionPoints);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *certificatePolicies NS_SWIFT_NAME(certificatePolicies);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *policyMappings NS_SWIFT_NAME(policyMappings);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *authorityKeyIdentifier NS_SWIFT_NAME(authorityKeyIdentifier);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *policyConstraints NS_SWIFT_NAME(policyConstraints);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extendedKeyUsage NS_SWIFT_NAME(extendedKeyUsage);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *freshestCRL NS_SWIFT_NAME(freshestCRL);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *inhibitAnyPolicy NS_SWIFT_NAME(inhibitAnyPolicy);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *authorityInfoAccess NS_SWIFT_NAME(authorityInfoAccess);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *subjectInfoAccess NS_SWIFT_NAME(subjectInfoAccess);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *logoType NS_SWIFT_NAME(logoType);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *biometricInfo NS_SWIFT_NAME(biometricInfo);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *qCStatements NS_SWIFT_NAME(qCStatements);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *auditIdentity NS_SWIFT_NAME(auditIdentity);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *noRevAvail NS_SWIFT_NAME(noRevAvail);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *targetInformation NS_SWIFT_NAME(targetInformation);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *expiredCertsOnCRL NS_SWIFT_NAME(expiredCertsOnCRL);

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)subjectDirectoryAttributes;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)subjectKeyIdentifier;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)keyUsage;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)privateKeyUsagePeriod;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)subjectAlternativeName;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)issuerAlternativeName;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)basicConstraints;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)cRLNumber;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)reasonCode;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)instructionCode;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)invalidityDate;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)deltaCRLIndicator;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)issuingDistributionPoint;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)certificateIssuer;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)nameConstraints;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)cRLDistributionPoints;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)certificatePolicies;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)policyMappings;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)authorityKeyIdentifier;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)policyConstraints;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)extendedKeyUsage;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)freshestCRL;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)inhibitAnyPolicy;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)authorityInfoAccess;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)subjectInfoAccess;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)logoType;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)biometricInfo;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)qCStatements;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)auditIdentity;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)noRevAvail;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)targetInformation;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)expiredCertsOnCRL;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)extnId
                                       withLibOrgBouncycastleAsn1ASN1Boolean:(LibOrgBouncycastleAsn1ASN1Boolean *)critical
                                   withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)value;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)extnId
                                                                 withBoolean:(jboolean)critical
                                   withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)value;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)extnId
                                                                 withBoolean:(jboolean)critical
                                                               withByteArray:(IOSByteArray *)value;

- (jboolean)isEqual:(id)o;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getExtnId;

- (LibOrgBouncycastleAsn1ASN1OctetString *)getExtnValue;

+ (LibOrgBouncycastleAsn1X509Extension *)getInstanceWithId:(id)obj;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getParsedValue;

- (NSUInteger)hash;

- (jboolean)isCritical;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleAsn1X509Extension)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_subjectDirectoryAttributes(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_subjectDirectoryAttributes;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, subjectDirectoryAttributes, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_subjectKeyIdentifier(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_subjectKeyIdentifier;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, subjectKeyIdentifier, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_keyUsage(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_keyUsage;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, keyUsage, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_privateKeyUsagePeriod(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_privateKeyUsagePeriod;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, privateKeyUsagePeriod, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_subjectAlternativeName(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_subjectAlternativeName;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, subjectAlternativeName, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_issuerAlternativeName(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_issuerAlternativeName;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, issuerAlternativeName, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_basicConstraints(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_basicConstraints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, basicConstraints, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_cRLNumber(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_cRLNumber;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, cRLNumber, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_reasonCode(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_reasonCode;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, reasonCode, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_instructionCode(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_instructionCode;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, instructionCode, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_invalidityDate(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_invalidityDate;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, invalidityDate, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_deltaCRLIndicator(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_deltaCRLIndicator;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, deltaCRLIndicator, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_issuingDistributionPoint(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_issuingDistributionPoint;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, issuingDistributionPoint, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_certificateIssuer(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_certificateIssuer;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, certificateIssuer, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_nameConstraints(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_nameConstraints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, nameConstraints, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_cRLDistributionPoints(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_cRLDistributionPoints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, cRLDistributionPoints, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_certificatePolicies(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_certificatePolicies;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, certificatePolicies, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_policyMappings(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_policyMappings;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, policyMappings, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_authorityKeyIdentifier(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_authorityKeyIdentifier;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, authorityKeyIdentifier, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_policyConstraints(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_policyConstraints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, policyConstraints, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_extendedKeyUsage(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_extendedKeyUsage;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, extendedKeyUsage, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_freshestCRL(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_freshestCRL;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, freshestCRL, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_inhibitAnyPolicy(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_inhibitAnyPolicy;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, inhibitAnyPolicy, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_authorityInfoAccess(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_authorityInfoAccess;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, authorityInfoAccess, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_subjectInfoAccess(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_subjectInfoAccess;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, subjectInfoAccess, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_logoType(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_logoType;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, logoType, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_biometricInfo(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_biometricInfo;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, biometricInfo, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_qCStatements(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_qCStatements;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, qCStatements, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_auditIdentity(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_auditIdentity;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, auditIdentity, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_noRevAvail(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_noRevAvail;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, noRevAvail, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_targetInformation(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_targetInformation;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, targetInformation, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_get_expiredCertsOnCRL(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_expiredCertsOnCRL;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509Extension, expiredCertsOnCRL, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1X509Extension *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, LibOrgBouncycastleAsn1ASN1Boolean *critical, LibOrgBouncycastleAsn1ASN1OctetString *value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509Extension *new_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, LibOrgBouncycastleAsn1ASN1Boolean *critical, LibOrgBouncycastleAsn1ASN1OctetString *value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509Extension *create_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, LibOrgBouncycastleAsn1ASN1Boolean *critical, LibOrgBouncycastleAsn1ASN1OctetString *value);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_(LibOrgBouncycastleAsn1X509Extension *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, IOSByteArray *value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509Extension *new_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, IOSByteArray *value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509Extension *create_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, IOSByteArray *value);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1X509Extension *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, LibOrgBouncycastleAsn1ASN1OctetString *value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509Extension *new_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, LibOrgBouncycastleAsn1ASN1OctetString *value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509Extension *create_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, LibOrgBouncycastleAsn1ASN1OctetString *value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509Extension *LibOrgBouncycastleAsn1X509Extension_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509Extension)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Extension_H