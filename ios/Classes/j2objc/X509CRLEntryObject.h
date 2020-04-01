//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/X509CRLEntryObject.java
//

#ifndef X509CRLEntryObject_H
#define X509CRLEntryObject_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/cert/X509CRLEntry.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class JavaUtilDate;
@class JavaxSecurityAuthX500X500Principal;
@class LibOrgBouncycastleAsn1X500X500Name;
@class LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry;
@protocol JavaUtilSet;

@interface LibOrgBouncycastleJceProviderX509CRLEntryObject : JavaSecurityCertX509CRLEntry

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509TBSCertList_CRLEntry:(LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *)c;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509TBSCertList_CRLEntry:(LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *)c
                                                                     withBoolean:(jboolean)isIndirect
                                          withLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)previousCertificateIssuer;

- (jboolean)isEqual:(id)o;

- (JavaxSecurityAuthX500X500Principal *)getCertificateIssuer;

- (id<JavaUtilSet>)getCriticalExtensionOIDs;

- (IOSByteArray *)getEncoded;

- (IOSByteArray *)getExtensionValueWithNSString:(NSString *)oid;

- (id<JavaUtilSet>)getNonCriticalExtensionOIDs;

- (JavaUtilDate *)getRevocationDate;

- (JavaMathBigInteger *)getSerialNumber;

- (jboolean)hasExtensions;

- (NSUInteger)hash;

- (jboolean)hasUnsupportedCriticalExtension;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceProviderX509CRLEntryObject)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderX509CRLEntryObject_initWithLibOrgBouncycastleAsn1X509TBSCertList_CRLEntry_(LibOrgBouncycastleJceProviderX509CRLEntryObject *self, LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *c);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderX509CRLEntryObject *new_LibOrgBouncycastleJceProviderX509CRLEntryObject_initWithLibOrgBouncycastleAsn1X509TBSCertList_CRLEntry_(LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *c) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderX509CRLEntryObject *create_LibOrgBouncycastleJceProviderX509CRLEntryObject_initWithLibOrgBouncycastleAsn1X509TBSCertList_CRLEntry_(LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *c);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderX509CRLEntryObject_initWithLibOrgBouncycastleAsn1X509TBSCertList_CRLEntry_withBoolean_withLibOrgBouncycastleAsn1X500X500Name_(LibOrgBouncycastleJceProviderX509CRLEntryObject *self, LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *c, jboolean isIndirect, LibOrgBouncycastleAsn1X500X500Name *previousCertificateIssuer);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderX509CRLEntryObject *new_LibOrgBouncycastleJceProviderX509CRLEntryObject_initWithLibOrgBouncycastleAsn1X509TBSCertList_CRLEntry_withBoolean_withLibOrgBouncycastleAsn1X500X500Name_(LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *c, jboolean isIndirect, LibOrgBouncycastleAsn1X500X500Name *previousCertificateIssuer) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderX509CRLEntryObject *create_LibOrgBouncycastleJceProviderX509CRLEntryObject_initWithLibOrgBouncycastleAsn1X509TBSCertList_CRLEntry_withBoolean_withLibOrgBouncycastleAsn1X500X500Name_(LibOrgBouncycastleAsn1X509TBSCertList_CRLEntry *c, jboolean isIndirect, LibOrgBouncycastleAsn1X500X500Name *previousCertificateIssuer);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderX509CRLEntryObject)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509CRLEntryObject_H