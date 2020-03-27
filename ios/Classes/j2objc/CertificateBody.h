//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/eac/CertificateBody.java
//

#ifndef CertificateBody_H
#define CertificateBody_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ApplicationSpecific;
@class LibOrgBouncycastleAsn1ASN1InputStream;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1EacCertificateHolderAuthorization;
@class LibOrgBouncycastleAsn1EacCertificateHolderReference;
@class LibOrgBouncycastleAsn1EacCertificationAuthorityReference;
@class LibOrgBouncycastleAsn1EacPackedDate;
@class LibOrgBouncycastleAsn1EacPublicKeyDataObject;

@interface LibOrgBouncycastleAsn1EacCertificateBody : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1ASN1InputStream *seq_;
}
@property (readonly, class) jint profileType NS_SWIFT_NAME(profileType);
@property (readonly, class) jint requestType NS_SWIFT_NAME(requestType);

+ (jint)profileType;

+ (jint)requestType;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific:(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *)certificateProfileIdentifier
                   withLibOrgBouncycastleAsn1EacCertificationAuthorityReference:(LibOrgBouncycastleAsn1EacCertificationAuthorityReference *)certificationAuthorityReference
                               withLibOrgBouncycastleAsn1EacPublicKeyDataObject:(LibOrgBouncycastleAsn1EacPublicKeyDataObject *)publicKey
                        withLibOrgBouncycastleAsn1EacCertificateHolderReference:(LibOrgBouncycastleAsn1EacCertificateHolderReference *)certificateHolderReference
                    withLibOrgBouncycastleAsn1EacCertificateHolderAuthorization:(LibOrgBouncycastleAsn1EacCertificateHolderAuthorization *)certificateHolderAuthorization
                                        withLibOrgBouncycastleAsn1EacPackedDate:(LibOrgBouncycastleAsn1EacPackedDate *)certificateEffectiveDate
                                        withLibOrgBouncycastleAsn1EacPackedDate:(LibOrgBouncycastleAsn1EacPackedDate *)certificateExpirationDate;

- (LibOrgBouncycastleAsn1EacPackedDate *)getCertificateEffectiveDate;

- (LibOrgBouncycastleAsn1EacPackedDate *)getCertificateExpirationDate;

- (LibOrgBouncycastleAsn1EacCertificateHolderAuthorization *)getCertificateHolderAuthorization;

- (LibOrgBouncycastleAsn1EacCertificateHolderReference *)getCertificateHolderReference;

- (LibOrgBouncycastleAsn1ASN1ApplicationSpecific *)getCertificateProfileIdentifier;

- (jint)getCertificateType;

- (LibOrgBouncycastleAsn1EacCertificationAuthorityReference *)getCertificationAuthorityReference;

+ (LibOrgBouncycastleAsn1EacCertificateBody *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1EacPublicKeyDataObject *)getPublicKey;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1EacCertificateBody)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EacCertificateBody, seq_, LibOrgBouncycastleAsn1ASN1InputStream *)

inline jint LibOrgBouncycastleAsn1EacCertificateBody_get_profileType(void);
#define LibOrgBouncycastleAsn1EacCertificateBody_profileType 127
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1EacCertificateBody, profileType, jint)

inline jint LibOrgBouncycastleAsn1EacCertificateBody_get_requestType(void);
#define LibOrgBouncycastleAsn1EacCertificateBody_requestType 13
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1EacCertificateBody, requestType, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EacCertificateBody_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_withLibOrgBouncycastleAsn1EacCertificationAuthorityReference_withLibOrgBouncycastleAsn1EacPublicKeyDataObject_withLibOrgBouncycastleAsn1EacCertificateHolderReference_withLibOrgBouncycastleAsn1EacCertificateHolderAuthorization_withLibOrgBouncycastleAsn1EacPackedDate_withLibOrgBouncycastleAsn1EacPackedDate_(LibOrgBouncycastleAsn1EacCertificateBody *self, LibOrgBouncycastleAsn1ASN1ApplicationSpecific *certificateProfileIdentifier, LibOrgBouncycastleAsn1EacCertificationAuthorityReference *certificationAuthorityReference, LibOrgBouncycastleAsn1EacPublicKeyDataObject *publicKey, LibOrgBouncycastleAsn1EacCertificateHolderReference *certificateHolderReference, LibOrgBouncycastleAsn1EacCertificateHolderAuthorization *certificateHolderAuthorization, LibOrgBouncycastleAsn1EacPackedDate *certificateEffectiveDate, LibOrgBouncycastleAsn1EacPackedDate *certificateExpirationDate);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacCertificateBody *new_LibOrgBouncycastleAsn1EacCertificateBody_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_withLibOrgBouncycastleAsn1EacCertificationAuthorityReference_withLibOrgBouncycastleAsn1EacPublicKeyDataObject_withLibOrgBouncycastleAsn1EacCertificateHolderReference_withLibOrgBouncycastleAsn1EacCertificateHolderAuthorization_withLibOrgBouncycastleAsn1EacPackedDate_withLibOrgBouncycastleAsn1EacPackedDate_(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *certificateProfileIdentifier, LibOrgBouncycastleAsn1EacCertificationAuthorityReference *certificationAuthorityReference, LibOrgBouncycastleAsn1EacPublicKeyDataObject *publicKey, LibOrgBouncycastleAsn1EacCertificateHolderReference *certificateHolderReference, LibOrgBouncycastleAsn1EacCertificateHolderAuthorization *certificateHolderAuthorization, LibOrgBouncycastleAsn1EacPackedDate *certificateEffectiveDate, LibOrgBouncycastleAsn1EacPackedDate *certificateExpirationDate) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacCertificateBody *create_LibOrgBouncycastleAsn1EacCertificateBody_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_withLibOrgBouncycastleAsn1EacCertificationAuthorityReference_withLibOrgBouncycastleAsn1EacPublicKeyDataObject_withLibOrgBouncycastleAsn1EacCertificateHolderReference_withLibOrgBouncycastleAsn1EacCertificateHolderAuthorization_withLibOrgBouncycastleAsn1EacPackedDate_withLibOrgBouncycastleAsn1EacPackedDate_(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *certificateProfileIdentifier, LibOrgBouncycastleAsn1EacCertificationAuthorityReference *certificationAuthorityReference, LibOrgBouncycastleAsn1EacPublicKeyDataObject *publicKey, LibOrgBouncycastleAsn1EacCertificateHolderReference *certificateHolderReference, LibOrgBouncycastleAsn1EacCertificateHolderAuthorization *certificateHolderAuthorization, LibOrgBouncycastleAsn1EacPackedDate *certificateEffectiveDate, LibOrgBouncycastleAsn1EacPackedDate *certificateExpirationDate);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacCertificateBody *LibOrgBouncycastleAsn1EacCertificateBody_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EacCertificateBody)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertificateBody_H
