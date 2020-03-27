//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/IssuingDistributionPoint.java
//

#ifndef IssuingDistributionPoint_H
#define IssuingDistributionPoint_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1X509DistributionPointName;
@class LibOrgBouncycastleAsn1X509ReasonFlags;

@interface LibOrgBouncycastleAsn1X509IssuingDistributionPoint : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509DistributionPointName:(LibOrgBouncycastleAsn1X509DistributionPointName *)distributionPoint
                                                                      withBoolean:(jboolean)indirectCRL
                                                                      withBoolean:(jboolean)onlyContainsAttributeCerts;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509DistributionPointName:(LibOrgBouncycastleAsn1X509DistributionPointName *)distributionPoint
                                                                      withBoolean:(jboolean)onlyContainsUserCerts
                                                                      withBoolean:(jboolean)onlyContainsCACerts
                                        withLibOrgBouncycastleAsn1X509ReasonFlags:(LibOrgBouncycastleAsn1X509ReasonFlags *)onlySomeReasons
                                                                      withBoolean:(jboolean)indirectCRL
                                                                      withBoolean:(jboolean)onlyContainsAttributeCerts;

- (LibOrgBouncycastleAsn1X509DistributionPointName *)getDistributionPoint;

+ (LibOrgBouncycastleAsn1X509IssuingDistributionPoint *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                                  withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1X509IssuingDistributionPoint *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1X509ReasonFlags *)getOnlySomeReasons;

- (jboolean)isIndirectCRL;

- (jboolean)onlyContainsAttributeCerts;

- (jboolean)onlyContainsCACerts;

- (jboolean)onlyContainsUserCerts;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509IssuingDistributionPoint)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuingDistributionPoint *LibOrgBouncycastleAsn1X509IssuingDistributionPoint_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuingDistributionPoint *LibOrgBouncycastleAsn1X509IssuingDistributionPoint_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509IssuingDistributionPoint_initWithLibOrgBouncycastleAsn1X509DistributionPointName_withBoolean_withBoolean_withLibOrgBouncycastleAsn1X509ReasonFlags_withBoolean_withBoolean_(LibOrgBouncycastleAsn1X509IssuingDistributionPoint *self, LibOrgBouncycastleAsn1X509DistributionPointName *distributionPoint, jboolean onlyContainsUserCerts, jboolean onlyContainsCACerts, LibOrgBouncycastleAsn1X509ReasonFlags *onlySomeReasons, jboolean indirectCRL, jboolean onlyContainsAttributeCerts);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuingDistributionPoint *new_LibOrgBouncycastleAsn1X509IssuingDistributionPoint_initWithLibOrgBouncycastleAsn1X509DistributionPointName_withBoolean_withBoolean_withLibOrgBouncycastleAsn1X509ReasonFlags_withBoolean_withBoolean_(LibOrgBouncycastleAsn1X509DistributionPointName *distributionPoint, jboolean onlyContainsUserCerts, jboolean onlyContainsCACerts, LibOrgBouncycastleAsn1X509ReasonFlags *onlySomeReasons, jboolean indirectCRL, jboolean onlyContainsAttributeCerts) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuingDistributionPoint *create_LibOrgBouncycastleAsn1X509IssuingDistributionPoint_initWithLibOrgBouncycastleAsn1X509DistributionPointName_withBoolean_withBoolean_withLibOrgBouncycastleAsn1X509ReasonFlags_withBoolean_withBoolean_(LibOrgBouncycastleAsn1X509DistributionPointName *distributionPoint, jboolean onlyContainsUserCerts, jboolean onlyContainsCACerts, LibOrgBouncycastleAsn1X509ReasonFlags *onlySomeReasons, jboolean indirectCRL, jboolean onlyContainsAttributeCerts);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509IssuingDistributionPoint_initWithLibOrgBouncycastleAsn1X509DistributionPointName_withBoolean_withBoolean_(LibOrgBouncycastleAsn1X509IssuingDistributionPoint *self, LibOrgBouncycastleAsn1X509DistributionPointName *distributionPoint, jboolean indirectCRL, jboolean onlyContainsAttributeCerts);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuingDistributionPoint *new_LibOrgBouncycastleAsn1X509IssuingDistributionPoint_initWithLibOrgBouncycastleAsn1X509DistributionPointName_withBoolean_withBoolean_(LibOrgBouncycastleAsn1X509DistributionPointName *distributionPoint, jboolean indirectCRL, jboolean onlyContainsAttributeCerts) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuingDistributionPoint *create_LibOrgBouncycastleAsn1X509IssuingDistributionPoint_initWithLibOrgBouncycastleAsn1X509DistributionPointName_withBoolean_withBoolean_(LibOrgBouncycastleAsn1X509DistributionPointName *distributionPoint, jboolean indirectCRL, jboolean onlyContainsAttributeCerts);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509IssuingDistributionPoint)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // IssuingDistributionPoint_H