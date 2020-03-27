//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/pkcs/EncryptedPrivateKeyInfo.java
//

#ifndef EncryptedPrivateKeyInfo_H
#define EncryptedPrivateKeyInfo_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)algId
                                                                  withByteArray:(IOSByteArray *)encoding;

- (IOSByteArray *)getEncryptedData;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getEncryptionAlgorithm;

+ (LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *encoding);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *new_LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *encoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *create_LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *encoding);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // EncryptedPrivateKeyInfo_H
