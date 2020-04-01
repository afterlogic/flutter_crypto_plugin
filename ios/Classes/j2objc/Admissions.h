//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/isismtt/x509/Admissions.java
//

#ifndef Admissions_H
#define Admissions_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1IsismttX509NamingAuthority;
@class LibOrgBouncycastleAsn1X509GeneralName;

@interface LibOrgBouncycastleAsn1IsismttX509Admissions : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)admissionAuthority
                   withLibOrgBouncycastleAsn1IsismttX509NamingAuthority:(LibOrgBouncycastleAsn1IsismttX509NamingAuthority *)namingAuthority
               withLibOrgBouncycastleAsn1IsismttX509ProfessionInfoArray:(IOSObjectArray *)professionInfos;

- (LibOrgBouncycastleAsn1X509GeneralName *)getAdmissionAuthority;

+ (LibOrgBouncycastleAsn1IsismttX509Admissions *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1IsismttX509NamingAuthority *)getNamingAuthority;

- (IOSObjectArray *)getProfessionInfos;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1IsismttX509Admissions)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttX509Admissions *LibOrgBouncycastleAsn1IsismttX509Admissions_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1IsismttX509Admissions_initWithLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1IsismttX509NamingAuthority_withLibOrgBouncycastleAsn1IsismttX509ProfessionInfoArray_(LibOrgBouncycastleAsn1IsismttX509Admissions *self, LibOrgBouncycastleAsn1X509GeneralName *admissionAuthority, LibOrgBouncycastleAsn1IsismttX509NamingAuthority *namingAuthority, IOSObjectArray *professionInfos);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttX509Admissions *new_LibOrgBouncycastleAsn1IsismttX509Admissions_initWithLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1IsismttX509NamingAuthority_withLibOrgBouncycastleAsn1IsismttX509ProfessionInfoArray_(LibOrgBouncycastleAsn1X509GeneralName *admissionAuthority, LibOrgBouncycastleAsn1IsismttX509NamingAuthority *namingAuthority, IOSObjectArray *professionInfos) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttX509Admissions *create_LibOrgBouncycastleAsn1IsismttX509Admissions_initWithLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1IsismttX509NamingAuthority_withLibOrgBouncycastleAsn1IsismttX509ProfessionInfoArray_(LibOrgBouncycastleAsn1X509GeneralName *admissionAuthority, LibOrgBouncycastleAsn1IsismttX509NamingAuthority *namingAuthority, IOSObjectArray *professionInfos);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1IsismttX509Admissions)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Admissions_H