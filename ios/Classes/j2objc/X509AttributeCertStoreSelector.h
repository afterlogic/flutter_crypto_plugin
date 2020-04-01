//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/X509AttributeCertStoreSelector.java
//

#ifndef X509AttributeCertStoreSelector_H
#define X509AttributeCertStoreSelector_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Selector.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class JavaUtilDate;
@class LibOrgBouncycastleAsn1X509GeneralName;
@class LibOrgBouncycastleX509AttributeCertificateHolder;
@class LibOrgBouncycastleX509AttributeCertificateIssuer;
@protocol JavaUtilCollection;
@protocol LibOrgBouncycastleX509X509AttributeCertificate;

@interface LibOrgBouncycastleX509X509AttributeCertStoreSelector : NSObject < LibOrgBouncycastleUtilSelector >

#pragma mark Public

- (instancetype __nonnull)init;

- (void)addTargetGroupWithByteArray:(IOSByteArray *)name;

- (void)addTargetGroupWithLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)group;

- (void)addTargetNameWithByteArray:(IOSByteArray *)name;

- (void)addTargetNameWithLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)name;

- (id)java_clone;

- (id<LibOrgBouncycastleX509X509AttributeCertificate>)getAttributeCert;

- (JavaUtilDate *)getAttributeCertificateValid;

- (LibOrgBouncycastleX509AttributeCertificateHolder *)getHolder;

- (LibOrgBouncycastleX509AttributeCertificateIssuer *)getIssuer;

- (JavaMathBigInteger *)getSerialNumber;

- (id<JavaUtilCollection>)getTargetGroups;

- (id<JavaUtilCollection>)getTargetNames;

- (jboolean)matchWithId:(id)obj;

- (void)setAttributeCertWithLibOrgBouncycastleX509X509AttributeCertificate:(id<LibOrgBouncycastleX509X509AttributeCertificate>)attributeCert;

- (void)setAttributeCertificateValidWithJavaUtilDate:(JavaUtilDate *)attributeCertificateValid;

- (void)setHolderWithLibOrgBouncycastleX509AttributeCertificateHolder:(LibOrgBouncycastleX509AttributeCertificateHolder *)holder;

- (void)setIssuerWithLibOrgBouncycastleX509AttributeCertificateIssuer:(LibOrgBouncycastleX509AttributeCertificateIssuer *)issuer;

- (void)setSerialNumberWithJavaMathBigInteger:(JavaMathBigInteger *)serialNumber;

- (void)setTargetGroupsWithJavaUtilCollection:(id<JavaUtilCollection>)names;

- (void)setTargetNamesWithJavaUtilCollection:(id<JavaUtilCollection>)names;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleX509X509AttributeCertStoreSelector)

FOUNDATION_EXPORT void LibOrgBouncycastleX509X509AttributeCertStoreSelector_init(LibOrgBouncycastleX509X509AttributeCertStoreSelector *self);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509AttributeCertStoreSelector *new_LibOrgBouncycastleX509X509AttributeCertStoreSelector_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509X509AttributeCertStoreSelector *create_LibOrgBouncycastleX509X509AttributeCertStoreSelector_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509X509AttributeCertStoreSelector)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509AttributeCertStoreSelector_H