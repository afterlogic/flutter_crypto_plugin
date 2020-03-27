//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x9/ECNamedCurveTable.java
//

#ifndef ECNamedCurveTable_H
#define ECNamedCurveTable_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1X9X9ECParameters;
@protocol JavaUtilEnumeration;

@interface LibOrgBouncycastleAsn1X9ECNamedCurveTable : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (LibOrgBouncycastleAsn1X9X9ECParameters *)getByNameWithNSString:(NSString *)name;

+ (LibOrgBouncycastleAsn1X9X9ECParameters *)getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid;

+ (NSString *)getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid;

+ (id<JavaUtilEnumeration>)getNames;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getOIDWithNSString:(NSString *)name;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X9ECNamedCurveTable)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X9ECNamedCurveTable_init(LibOrgBouncycastleAsn1X9ECNamedCurveTable *self);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9ECNamedCurveTable *new_LibOrgBouncycastleAsn1X9ECNamedCurveTable_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9ECNamedCurveTable *create_LibOrgBouncycastleAsn1X9ECNamedCurveTable_init(void);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParameters *LibOrgBouncycastleAsn1X9ECNamedCurveTable_getByNameWithNSString_(NSString *name);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X9ECNamedCurveTable_getOIDWithNSString_(NSString *name);

FOUNDATION_EXPORT NSString *LibOrgBouncycastleAsn1X9ECNamedCurveTable_getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParameters *LibOrgBouncycastleAsn1X9ECNamedCurveTable_getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid);

FOUNDATION_EXPORT id<JavaUtilEnumeration> LibOrgBouncycastleAsn1X9ECNamedCurveTable_getNames(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X9ECNamedCurveTable)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECNamedCurveTable_H
