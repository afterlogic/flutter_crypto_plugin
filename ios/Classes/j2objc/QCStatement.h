//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/qualified/QCStatement.java
//

#ifndef QCStatement_H
#define QCStatement_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "ETSIQCObjectIdentifiers.h"
#include "J2ObjC_header.h"
#include "RFC3739QCObjectIdentifiers.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1X509QualifiedQCStatement : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1X509QualifiedETSIQCObjectIdentifiers, LibOrgBouncycastleAsn1X509QualifiedRFC3739QCObjectIdentifiers > {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *qcStatementId_;
  id<LibOrgBouncycastleAsn1ASN1Encodable> qcStatementInfo_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)qcStatementId;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)qcStatementId
                                     withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)qcStatementInfo;

+ (LibOrgBouncycastleAsn1X509QualifiedQCStatement *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getStatementId;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getStatementInfo;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509QualifiedQCStatement)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509QualifiedQCStatement, qcStatementId_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509QualifiedQCStatement, qcStatementInfo_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedQCStatement *LibOrgBouncycastleAsn1X509QualifiedQCStatement_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509QualifiedQCStatement_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1X509QualifiedQCStatement *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *qcStatementId);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedQCStatement *new_LibOrgBouncycastleAsn1X509QualifiedQCStatement_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *qcStatementId) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedQCStatement *create_LibOrgBouncycastleAsn1X509QualifiedQCStatement_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *qcStatementId);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509QualifiedQCStatement_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1X509QualifiedQCStatement *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *qcStatementId, id<LibOrgBouncycastleAsn1ASN1Encodable> qcStatementInfo);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedQCStatement *new_LibOrgBouncycastleAsn1X509QualifiedQCStatement_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *qcStatementId, id<LibOrgBouncycastleAsn1ASN1Encodable> qcStatementInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedQCStatement *create_LibOrgBouncycastleAsn1X509QualifiedQCStatement_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *qcStatementId, id<LibOrgBouncycastleAsn1ASN1Encodable> qcStatementInfo);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509QualifiedQCStatement)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // QCStatement_H
