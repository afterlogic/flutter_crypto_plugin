//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/bc/EncryptedObjectStoreData.java
//

#ifndef EncryptedObjectStoreData_H
#define EncryptedObjectStoreData_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1OctetString;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1BcEncryptedObjectStoreData : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)encryptionAlgorithm
                                                                  withByteArray:(IOSByteArray *)encryptedContent;

- (LibOrgBouncycastleAsn1ASN1OctetString *)getEncryptedContent;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getEncryptionAlgorithm;

+ (LibOrgBouncycastleAsn1BcEncryptedObjectStoreData *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1BcEncryptedObjectStoreData)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BcEncryptedObjectStoreData_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1BcEncryptedObjectStoreData *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *encryptionAlgorithm, IOSByteArray *encryptedContent);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcEncryptedObjectStoreData *new_LibOrgBouncycastleAsn1BcEncryptedObjectStoreData_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *encryptionAlgorithm, IOSByteArray *encryptedContent) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcEncryptedObjectStoreData *create_LibOrgBouncycastleAsn1BcEncryptedObjectStoreData_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *encryptionAlgorithm, IOSByteArray *encryptedContent);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcEncryptedObjectStoreData *LibOrgBouncycastleAsn1BcEncryptedObjectStoreData_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1BcEncryptedObjectStoreData)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // EncryptedObjectStoreData_H
