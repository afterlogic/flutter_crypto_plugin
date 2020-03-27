//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/CertifiedKeyPair.java
//

#ifndef CertifiedKeyPair_H
#define CertifiedKeyPair_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1CmpCertOrEncCert;
@class LibOrgBouncycastleAsn1CrmfEncryptedValue;
@class LibOrgBouncycastleAsn1CrmfPKIPublicationInfo;

@interface LibOrgBouncycastleAsn1CmpCertifiedKeyPair : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmpCertOrEncCert:(LibOrgBouncycastleAsn1CmpCertOrEncCert *)certOrEncCert;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmpCertOrEncCert:(LibOrgBouncycastleAsn1CmpCertOrEncCert *)certOrEncCert
                            withLibOrgBouncycastleAsn1CrmfEncryptedValue:(LibOrgBouncycastleAsn1CrmfEncryptedValue *)privateKey
                        withLibOrgBouncycastleAsn1CrmfPKIPublicationInfo:(LibOrgBouncycastleAsn1CrmfPKIPublicationInfo *)publicationInfo;

- (LibOrgBouncycastleAsn1CmpCertOrEncCert *)getCertOrEncCert;

+ (LibOrgBouncycastleAsn1CmpCertifiedKeyPair *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1CrmfEncryptedValue *)getPrivateKey;

- (LibOrgBouncycastleAsn1CrmfPKIPublicationInfo *)getPublicationInfo;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmpCertifiedKeyPair)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpCertifiedKeyPair *LibOrgBouncycastleAsn1CmpCertifiedKeyPair_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpCertifiedKeyPair_initWithLibOrgBouncycastleAsn1CmpCertOrEncCert_(LibOrgBouncycastleAsn1CmpCertifiedKeyPair *self, LibOrgBouncycastleAsn1CmpCertOrEncCert *certOrEncCert);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpCertifiedKeyPair *new_LibOrgBouncycastleAsn1CmpCertifiedKeyPair_initWithLibOrgBouncycastleAsn1CmpCertOrEncCert_(LibOrgBouncycastleAsn1CmpCertOrEncCert *certOrEncCert) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpCertifiedKeyPair *create_LibOrgBouncycastleAsn1CmpCertifiedKeyPair_initWithLibOrgBouncycastleAsn1CmpCertOrEncCert_(LibOrgBouncycastleAsn1CmpCertOrEncCert *certOrEncCert);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpCertifiedKeyPair_initWithLibOrgBouncycastleAsn1CmpCertOrEncCert_withLibOrgBouncycastleAsn1CrmfEncryptedValue_withLibOrgBouncycastleAsn1CrmfPKIPublicationInfo_(LibOrgBouncycastleAsn1CmpCertifiedKeyPair *self, LibOrgBouncycastleAsn1CmpCertOrEncCert *certOrEncCert, LibOrgBouncycastleAsn1CrmfEncryptedValue *privateKey, LibOrgBouncycastleAsn1CrmfPKIPublicationInfo *publicationInfo);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpCertifiedKeyPair *new_LibOrgBouncycastleAsn1CmpCertifiedKeyPair_initWithLibOrgBouncycastleAsn1CmpCertOrEncCert_withLibOrgBouncycastleAsn1CrmfEncryptedValue_withLibOrgBouncycastleAsn1CrmfPKIPublicationInfo_(LibOrgBouncycastleAsn1CmpCertOrEncCert *certOrEncCert, LibOrgBouncycastleAsn1CrmfEncryptedValue *privateKey, LibOrgBouncycastleAsn1CrmfPKIPublicationInfo *publicationInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpCertifiedKeyPair *create_LibOrgBouncycastleAsn1CmpCertifiedKeyPair_initWithLibOrgBouncycastleAsn1CmpCertOrEncCert_withLibOrgBouncycastleAsn1CrmfEncryptedValue_withLibOrgBouncycastleAsn1CrmfPKIPublicationInfo_(LibOrgBouncycastleAsn1CmpCertOrEncCert *certOrEncCert, LibOrgBouncycastleAsn1CrmfEncryptedValue *privateKey, LibOrgBouncycastleAsn1CrmfPKIPublicationInfo *publicationInfo);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmpCertifiedKeyPair)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertifiedKeyPair_H