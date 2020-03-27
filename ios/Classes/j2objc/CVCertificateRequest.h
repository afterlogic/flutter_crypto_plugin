//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/eac/CVCertificateRequest.java
//

#ifndef CVCertificateRequest_H
#define CVCertificateRequest_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1EacCertificateBody;
@class LibOrgBouncycastleAsn1EacPublicKeyDataObject;

@interface LibOrgBouncycastleAsn1EacCVCertificateRequest : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (LibOrgBouncycastleAsn1EacCertificateBody *)getCertificateBody;

- (IOSByteArray *)getInnerSignature;

+ (LibOrgBouncycastleAsn1EacCVCertificateRequest *)getInstanceWithId:(id)obj;

- (IOSByteArray *)getOuterSignature;

- (LibOrgBouncycastleAsn1EacPublicKeyDataObject *)getPublicKey;

- (jboolean)hasOuterSignature;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1EacCVCertificateRequest)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacCVCertificateRequest *LibOrgBouncycastleAsn1EacCVCertificateRequest_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EacCVCertificateRequest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CVCertificateRequest_H
