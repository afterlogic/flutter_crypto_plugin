//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/X509CRLObject.java
//

#ifndef X509CRLObject_H
#define X509CRLObject_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/cert/X509CRL.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class JavaSecurityCertCertificate;
@class JavaSecurityCertX509CRLEntry;
@class JavaSecurityProvider;
@class JavaUtilDate;
@class JavaxSecurityAuthX500X500Principal;
@class LibOrgBouncycastleAsn1X509CertificateList;
@protocol JavaSecurityPrincipal;
@protocol JavaSecurityPublicKey;
@protocol JavaUtilSet;

@interface LibOrgBouncycastleJceProviderX509CRLObject : JavaSecurityCertX509CRL

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509CertificateList:(LibOrgBouncycastleAsn1X509CertificateList *)c;

- (jboolean)isEqual:(id)other;

- (id<JavaUtilSet>)getCriticalExtensionOIDs;

- (IOSByteArray *)getEncoded;

- (IOSByteArray *)getExtensionValueWithNSString:(NSString *)oid;

- (id<JavaSecurityPrincipal>)getIssuerDN;

- (JavaxSecurityAuthX500X500Principal *)getIssuerX500Principal;

- (JavaUtilDate *)getNextUpdate;

- (id<JavaUtilSet>)getNonCriticalExtensionOIDs;

- (JavaSecurityCertX509CRLEntry *)getRevokedCertificateWithJavaMathBigInteger:(JavaMathBigInteger *)serialNumber;

- (id<JavaUtilSet>)getRevokedCertificates;

- (NSString *)getSigAlgName;

- (NSString *)getSigAlgOID;

- (IOSByteArray *)getSigAlgParams;

- (IOSByteArray *)getSignature;

- (IOSByteArray *)getTBSCertList;

- (JavaUtilDate *)getThisUpdate;

- (jint)getVersion;

- (NSUInteger)hash;

- (jboolean)hasUnsupportedCriticalExtension;

+ (jboolean)isIndirectCRLWithJavaSecurityCertX509CRL:(JavaSecurityCertX509CRL *)crl;

- (jboolean)isRevokedWithJavaSecurityCertCertificate:(JavaSecurityCertCertificate *)cert;

- (NSString *)description;

- (void)verifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key;

- (void)verifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key
               withJavaSecurityProvider:(JavaSecurityProvider *)sigProvider;

- (void)verifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key
                           withNSString:(NSString *)sigProvider;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceProviderX509CRLObject)

FOUNDATION_EXPORT jboolean LibOrgBouncycastleJceProviderX509CRLObject_isIndirectCRLWithJavaSecurityCertX509CRL_(JavaSecurityCertX509CRL *crl);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderX509CRLObject_initWithLibOrgBouncycastleAsn1X509CertificateList_(LibOrgBouncycastleJceProviderX509CRLObject *self, LibOrgBouncycastleAsn1X509CertificateList *c);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderX509CRLObject *new_LibOrgBouncycastleJceProviderX509CRLObject_initWithLibOrgBouncycastleAsn1X509CertificateList_(LibOrgBouncycastleAsn1X509CertificateList *c) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderX509CRLObject *create_LibOrgBouncycastleJceProviderX509CRLObject_initWithLibOrgBouncycastleAsn1X509CertificateList_(LibOrgBouncycastleAsn1X509CertificateList *c);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderX509CRLObject)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509CRLObject_H