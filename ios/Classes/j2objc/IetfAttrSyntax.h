//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/IetfAttrSyntax.java
//

#ifndef IetfAttrSyntax_H
#define IetfAttrSyntax_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaUtilVector;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1X509GeneralNames;

@interface LibOrgBouncycastleAsn1X509IetfAttrSyntax : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1X509GeneralNames *policyAuthority_;
  JavaUtilVector *values_;
  jint valueChoice_;
}
@property (readonly, class) jint VALUE_OCTETS NS_SWIFT_NAME(VALUE_OCTETS);
@property (readonly, class) jint VALUE_OID NS_SWIFT_NAME(VALUE_OID);
@property (readonly, class) jint VALUE_UTF8 NS_SWIFT_NAME(VALUE_UTF8);

+ (jint)VALUE_OCTETS;

+ (jint)VALUE_OID;

+ (jint)VALUE_UTF8;

#pragma mark Public

+ (LibOrgBouncycastleAsn1X509IetfAttrSyntax *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1X509GeneralNames *)getPolicyAuthority;

- (IOSObjectArray *)getValues;

- (jint)getValueType;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509IetfAttrSyntax)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509IetfAttrSyntax, policyAuthority_, LibOrgBouncycastleAsn1X509GeneralNames *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509IetfAttrSyntax, values_, JavaUtilVector *)

inline jint LibOrgBouncycastleAsn1X509IetfAttrSyntax_get_VALUE_OCTETS(void);
#define LibOrgBouncycastleAsn1X509IetfAttrSyntax_VALUE_OCTETS 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1X509IetfAttrSyntax, VALUE_OCTETS, jint)

inline jint LibOrgBouncycastleAsn1X509IetfAttrSyntax_get_VALUE_OID(void);
#define LibOrgBouncycastleAsn1X509IetfAttrSyntax_VALUE_OID 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1X509IetfAttrSyntax, VALUE_OID, jint)

inline jint LibOrgBouncycastleAsn1X509IetfAttrSyntax_get_VALUE_UTF8(void);
#define LibOrgBouncycastleAsn1X509IetfAttrSyntax_VALUE_UTF8 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1X509IetfAttrSyntax, VALUE_UTF8, jint)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IetfAttrSyntax *LibOrgBouncycastleAsn1X509IetfAttrSyntax_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509IetfAttrSyntax)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // IetfAttrSyntax_H
