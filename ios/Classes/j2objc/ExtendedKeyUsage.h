//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/ExtendedKeyUsage.java
//

#ifndef ExtendedKeyUsage_H
#define ExtendedKeyUsage_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaUtilHashtable;
@class JavaUtilVector;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1X509Extensions;
@class LibOrgBouncycastleAsn1X509KeyPurposeId;

@interface LibOrgBouncycastleAsn1X509ExtendedKeyUsage : LibOrgBouncycastleAsn1ASN1Object {
 @public
  JavaUtilHashtable *usageTable_;
  LibOrgBouncycastleAsn1ASN1Sequence *seq_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509KeyPurposeId:(LibOrgBouncycastleAsn1X509KeyPurposeId *)usage;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509KeyPurposeIdArray:(IOSObjectArray *)usages;

- (instancetype __nonnull)initWithJavaUtilVector:(JavaUtilVector *)usages;

+ (LibOrgBouncycastleAsn1X509ExtendedKeyUsage *)fromExtensionsWithLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)extensions;

+ (LibOrgBouncycastleAsn1X509ExtendedKeyUsage *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                          withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1X509ExtendedKeyUsage *)getInstanceWithId:(id)obj;

- (IOSObjectArray *)getUsages;

- (jboolean)hasKeyPurposeIdWithLibOrgBouncycastleAsn1X509KeyPurposeId:(LibOrgBouncycastleAsn1X509KeyPurposeId *)keyPurposeId;

- (jint)size;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509ExtendedKeyUsage)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509ExtendedKeyUsage, usageTable_, JavaUtilHashtable *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509ExtendedKeyUsage, seq_, LibOrgBouncycastleAsn1ASN1Sequence *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509ExtendedKeyUsage *LibOrgBouncycastleAsn1X509ExtendedKeyUsage_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509ExtendedKeyUsage *LibOrgBouncycastleAsn1X509ExtendedKeyUsage_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509ExtendedKeyUsage *LibOrgBouncycastleAsn1X509ExtendedKeyUsage_fromExtensionsWithLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1X509Extensions *extensions);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeId_(LibOrgBouncycastleAsn1X509ExtendedKeyUsage *self, LibOrgBouncycastleAsn1X509KeyPurposeId *usage);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509ExtendedKeyUsage *new_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeId_(LibOrgBouncycastleAsn1X509KeyPurposeId *usage) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509ExtendedKeyUsage *create_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeId_(LibOrgBouncycastleAsn1X509KeyPurposeId *usage);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeIdArray_(LibOrgBouncycastleAsn1X509ExtendedKeyUsage *self, IOSObjectArray *usages);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509ExtendedKeyUsage *new_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeIdArray_(IOSObjectArray *usages) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509ExtendedKeyUsage *create_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithLibOrgBouncycastleAsn1X509KeyPurposeIdArray_(IOSObjectArray *usages);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithJavaUtilVector_(LibOrgBouncycastleAsn1X509ExtendedKeyUsage *self, JavaUtilVector *usages);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509ExtendedKeyUsage *new_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithJavaUtilVector_(JavaUtilVector *usages) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509ExtendedKeyUsage *create_LibOrgBouncycastleAsn1X509ExtendedKeyUsage_initWithJavaUtilVector_(JavaUtilVector *usages);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509ExtendedKeyUsage)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ExtendedKeyUsage_H