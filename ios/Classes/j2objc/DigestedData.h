//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/DigestedData.java
//

#ifndef DigestedData_H
#define DigestedData_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1CmsDigestedData : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)digestAlgorithm
                                withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo:(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)encapContentInfo
                                                                  withByteArray:(IOSByteArray *)digest;

- (IOSByteArray *)getDigest;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getDigestAlgorithm;

- (LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)getEncapContentInfo;

+ (LibOrgBouncycastleAsn1CmsDigestedData *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)ato
                                                                                     withBoolean:(jboolean)isExplicit;

+ (LibOrgBouncycastleAsn1CmsDigestedData *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmsDigestedData)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsDigestedData_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_withByteArray_(LibOrgBouncycastleAsn1CmsDigestedData *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digestAlgorithm, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *encapContentInfo, IOSByteArray *digest);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsDigestedData *new_LibOrgBouncycastleAsn1CmsDigestedData_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digestAlgorithm, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *encapContentInfo, IOSByteArray *digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsDigestedData *create_LibOrgBouncycastleAsn1CmsDigestedData_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digestAlgorithm, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *encapContentInfo, IOSByteArray *digest);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsDigestedData *LibOrgBouncycastleAsn1CmsDigestedData_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *ato, jboolean isExplicit);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsDigestedData *LibOrgBouncycastleAsn1CmsDigestedData_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmsDigestedData)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DigestedData_H
