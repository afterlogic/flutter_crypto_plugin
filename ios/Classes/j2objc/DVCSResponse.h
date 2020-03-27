//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/dvcs/DVCSResponse.java
//

#ifndef DVCSResponse_H
#define DVCSResponse_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Choice.h"
#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1DvcsDVCSCertInfo;
@class LibOrgBouncycastleAsn1DvcsDVCSErrorNotice;

@interface LibOrgBouncycastleAsn1DvcsDVCSResponse : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1ASN1Choice >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1DvcsDVCSCertInfo:(LibOrgBouncycastleAsn1DvcsDVCSCertInfo *)dvCertInfo;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1DvcsDVCSErrorNotice:(LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *)dvErrorNote;

- (LibOrgBouncycastleAsn1DvcsDVCSCertInfo *)getCertInfo;

- (LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *)getErrorNotice;

+ (LibOrgBouncycastleAsn1DvcsDVCSResponse *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1DvcsDVCSResponse *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DvcsDVCSResponse)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsDVCSResponse_initWithLibOrgBouncycastleAsn1DvcsDVCSCertInfo_(LibOrgBouncycastleAsn1DvcsDVCSResponse *self, LibOrgBouncycastleAsn1DvcsDVCSCertInfo *dvCertInfo);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSResponse *new_LibOrgBouncycastleAsn1DvcsDVCSResponse_initWithLibOrgBouncycastleAsn1DvcsDVCSCertInfo_(LibOrgBouncycastleAsn1DvcsDVCSCertInfo *dvCertInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSResponse *create_LibOrgBouncycastleAsn1DvcsDVCSResponse_initWithLibOrgBouncycastleAsn1DvcsDVCSCertInfo_(LibOrgBouncycastleAsn1DvcsDVCSCertInfo *dvCertInfo);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsDVCSResponse_initWithLibOrgBouncycastleAsn1DvcsDVCSErrorNotice_(LibOrgBouncycastleAsn1DvcsDVCSResponse *self, LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *dvErrorNote);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSResponse *new_LibOrgBouncycastleAsn1DvcsDVCSResponse_initWithLibOrgBouncycastleAsn1DvcsDVCSErrorNotice_(LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *dvErrorNote) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSResponse *create_LibOrgBouncycastleAsn1DvcsDVCSResponse_initWithLibOrgBouncycastleAsn1DvcsDVCSErrorNotice_(LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *dvErrorNote);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSResponse *LibOrgBouncycastleAsn1DvcsDVCSResponse_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSResponse *LibOrgBouncycastleAsn1DvcsDVCSResponse_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DvcsDVCSResponse)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DVCSResponse_H
