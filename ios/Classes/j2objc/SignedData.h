//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/pkcs/SignedData.java
//

#ifndef SignedData_H
#define SignedData_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"
#include "PKCSObjectIdentifiers.h"

@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1ASN1Set;
@class LibOrgBouncycastleAsn1PkcsContentInfo;

@interface LibOrgBouncycastleAsn1PkcsSignedData : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)_version
                                  withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)_digestAlgorithms
                          withLibOrgBouncycastleAsn1PkcsContentInfo:(LibOrgBouncycastleAsn1PkcsContentInfo *)_contentInfo
                                  withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)_certificates
                                  withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)_crls
                                  withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)_signerInfos;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (LibOrgBouncycastleAsn1ASN1Set *)getCertificates;

- (LibOrgBouncycastleAsn1PkcsContentInfo *)getContentInfo;

- (LibOrgBouncycastleAsn1ASN1Set *)getCRLs;

- (LibOrgBouncycastleAsn1ASN1Set *)getDigestAlgorithms;

+ (LibOrgBouncycastleAsn1PkcsSignedData *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Set *)getSignerInfos;

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1PkcsSignedData)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsSignedData *LibOrgBouncycastleAsn1PkcsSignedData_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1PkcsSignedData_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1PkcsContentInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1PkcsSignedData *self, LibOrgBouncycastleAsn1ASN1Integer *_version, LibOrgBouncycastleAsn1ASN1Set *_digestAlgorithms, LibOrgBouncycastleAsn1PkcsContentInfo *_contentInfo, LibOrgBouncycastleAsn1ASN1Set *_certificates, LibOrgBouncycastleAsn1ASN1Set *_crls, LibOrgBouncycastleAsn1ASN1Set *_signerInfos);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsSignedData *new_LibOrgBouncycastleAsn1PkcsSignedData_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1PkcsContentInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1ASN1Integer *_version, LibOrgBouncycastleAsn1ASN1Set *_digestAlgorithms, LibOrgBouncycastleAsn1PkcsContentInfo *_contentInfo, LibOrgBouncycastleAsn1ASN1Set *_certificates, LibOrgBouncycastleAsn1ASN1Set *_crls, LibOrgBouncycastleAsn1ASN1Set *_signerInfos) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsSignedData *create_LibOrgBouncycastleAsn1PkcsSignedData_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1PkcsContentInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1ASN1Integer *_version, LibOrgBouncycastleAsn1ASN1Set *_digestAlgorithms, LibOrgBouncycastleAsn1PkcsContentInfo *_contentInfo, LibOrgBouncycastleAsn1ASN1Set *_certificates, LibOrgBouncycastleAsn1ASN1Set *_crls, LibOrgBouncycastleAsn1ASN1Set *_signerInfos);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1PkcsSignedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1PkcsSignedData *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsSignedData *new_LibOrgBouncycastleAsn1PkcsSignedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsSignedData *create_LibOrgBouncycastleAsn1PkcsSignedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1PkcsSignedData)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SignedData_H
