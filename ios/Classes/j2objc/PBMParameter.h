//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/PBMParameter.java
//

#ifndef PBMParameter_H
#define PBMParameter_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1OctetString;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1CmpPBMParameter : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)salt
                      withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)owf
                                  withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)iterationCount
                      withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)mac;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)salt
withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)owf
                                    withInt:(jint)iterationCount
withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)mac;

+ (LibOrgBouncycastleAsn1CmpPBMParameter *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Integer *)getIterationCount;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getMac;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getOwf;

- (LibOrgBouncycastleAsn1ASN1OctetString *)getSalt;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmpPBMParameter)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPBMParameter *LibOrgBouncycastleAsn1CmpPBMParameter_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpPBMParameter_initWithByteArray_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withInt_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastleAsn1CmpPBMParameter *self, IOSByteArray *salt, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *owf, jint iterationCount, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *mac);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPBMParameter *new_LibOrgBouncycastleAsn1CmpPBMParameter_initWithByteArray_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withInt_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(IOSByteArray *salt, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *owf, jint iterationCount, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *mac) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPBMParameter *create_LibOrgBouncycastleAsn1CmpPBMParameter_initWithByteArray_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withInt_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(IOSByteArray *salt, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *owf, jint iterationCount, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *mac);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpPBMParameter_initWithLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastleAsn1CmpPBMParameter *self, LibOrgBouncycastleAsn1ASN1OctetString *salt, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *owf, LibOrgBouncycastleAsn1ASN1Integer *iterationCount, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *mac);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPBMParameter *new_LibOrgBouncycastleAsn1CmpPBMParameter_initWithLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastleAsn1ASN1OctetString *salt, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *owf, LibOrgBouncycastleAsn1ASN1Integer *iterationCount, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *mac) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPBMParameter *create_LibOrgBouncycastleAsn1CmpPBMParameter_initWithLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastleAsn1ASN1OctetString *salt, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *owf, LibOrgBouncycastleAsn1ASN1Integer *iterationCount, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *mac);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmpPBMParameter)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PBMParameter_H
