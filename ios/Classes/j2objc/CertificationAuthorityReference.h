//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/eac/CertificationAuthorityReference.java
//

#ifndef CertificationAuthorityReference_H
#define CertificationAuthorityReference_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "CertificateHolderReference.h"
#include "J2ObjC_header.h"

@class IOSByteArray;

@interface LibOrgBouncycastleAsn1EacCertificationAuthorityReference : LibOrgBouncycastleAsn1EacCertificateHolderReference

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)countryCode
                              withNSString:(NSString *)holderMnemonic
                              withNSString:(NSString *)sequenceNumber;

#pragma mark Package-Private

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)contents;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1EacCertificationAuthorityReference)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EacCertificationAuthorityReference_initWithNSString_withNSString_withNSString_(LibOrgBouncycastleAsn1EacCertificationAuthorityReference *self, NSString *countryCode, NSString *holderMnemonic, NSString *sequenceNumber);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacCertificationAuthorityReference *new_LibOrgBouncycastleAsn1EacCertificationAuthorityReference_initWithNSString_withNSString_withNSString_(NSString *countryCode, NSString *holderMnemonic, NSString *sequenceNumber) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacCertificationAuthorityReference *create_LibOrgBouncycastleAsn1EacCertificationAuthorityReference_initWithNSString_withNSString_withNSString_(NSString *countryCode, NSString *holderMnemonic, NSString *sequenceNumber);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EacCertificationAuthorityReference_initWithByteArray_(LibOrgBouncycastleAsn1EacCertificationAuthorityReference *self, IOSByteArray *contents);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacCertificationAuthorityReference *new_LibOrgBouncycastleAsn1EacCertificationAuthorityReference_initWithByteArray_(IOSByteArray *contents) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacCertificationAuthorityReference *create_LibOrgBouncycastleAsn1EacCertificationAuthorityReference_initWithByteArray_(IOSByteArray *contents);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EacCertificationAuthorityReference)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertificationAuthorityReference_H
