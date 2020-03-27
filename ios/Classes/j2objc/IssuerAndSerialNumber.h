//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/pkcs/IssuerAndSerialNumber.java
//

#ifndef IssuerAndSerialNumber_H
#define IssuerAndSerialNumber_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1X500X500Name;
@class LibOrgBouncycastleAsn1X509X509Name;

@interface LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1X500X500Name *name_;
  LibOrgBouncycastleAsn1ASN1Integer *certSerialNumber_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)name
                                              withJavaMathBigInteger:(JavaMathBigInteger *)certSerialNumber;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509X509Name:(LibOrgBouncycastleAsn1X509X509Name *)name
                               withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)certSerialNumber;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509X509Name:(LibOrgBouncycastleAsn1X509X509Name *)name
                                              withJavaMathBigInteger:(JavaMathBigInteger *)certSerialNumber;

- (LibOrgBouncycastleAsn1ASN1Integer *)getCertificateSerialNumber;

+ (LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1X500X500Name *)getName;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber, name_, LibOrgBouncycastleAsn1X500X500Name *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber, certSerialNumber_, LibOrgBouncycastleAsn1ASN1Integer *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_initWithLibOrgBouncycastleAsn1X509X509Name_withJavaMathBigInteger_(LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *self, LibOrgBouncycastleAsn1X509X509Name *name, JavaMathBigInteger *certSerialNumber);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *new_LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_initWithLibOrgBouncycastleAsn1X509X509Name_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X509X509Name *name, JavaMathBigInteger *certSerialNumber) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *create_LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_initWithLibOrgBouncycastleAsn1X509X509Name_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X509X509Name *name, JavaMathBigInteger *certSerialNumber);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_initWithLibOrgBouncycastleAsn1X509X509Name_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *self, LibOrgBouncycastleAsn1X509X509Name *name, LibOrgBouncycastleAsn1ASN1Integer *certSerialNumber);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *new_LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_initWithLibOrgBouncycastleAsn1X509X509Name_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X509X509Name *name, LibOrgBouncycastleAsn1ASN1Integer *certSerialNumber) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *create_LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_initWithLibOrgBouncycastleAsn1X509X509Name_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X509X509Name *name, LibOrgBouncycastleAsn1ASN1Integer *certSerialNumber);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_initWithLibOrgBouncycastleAsn1X500X500Name_withJavaMathBigInteger_(LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *self, LibOrgBouncycastleAsn1X500X500Name *name, JavaMathBigInteger *certSerialNumber);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *new_LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_initWithLibOrgBouncycastleAsn1X500X500Name_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X500X500Name *name, JavaMathBigInteger *certSerialNumber) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *create_LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_initWithLibOrgBouncycastleAsn1X500X500Name_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X500X500Name *name, JavaMathBigInteger *certSerialNumber);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // IssuerAndSerialNumber_H
