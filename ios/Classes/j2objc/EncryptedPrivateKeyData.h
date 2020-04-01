//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/bc/EncryptedPrivateKeyData.java
//

#ifndef EncryptedPrivateKeyData_H
#define EncryptedPrivateKeyData_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo;

@interface LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *)encryptedPrivateKeyInfo
                                 withLibOrgBouncycastleAsn1X509X509CertificateArray:(IOSObjectArray *)certificateChain;

- (IOSObjectArray *)getCertificateChain;

- (LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *)getEncryptedPrivateKeyInfo;

+ (LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_withLibOrgBouncycastleAsn1X509X509CertificateArray_(LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *self, LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *encryptedPrivateKeyInfo, IOSObjectArray *certificateChain);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *new_LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_withLibOrgBouncycastleAsn1X509X509CertificateArray_(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *encryptedPrivateKeyInfo, IOSObjectArray *certificateChain) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *create_LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_withLibOrgBouncycastleAsn1X509X509CertificateArray_(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *encryptedPrivateKeyInfo, IOSObjectArray *certificateChain);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // EncryptedPrivateKeyData_H