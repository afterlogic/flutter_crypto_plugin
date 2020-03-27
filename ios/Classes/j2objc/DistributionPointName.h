//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/DistributionPointName.java
//

#ifndef DistributionPointName_H
#define DistributionPointName_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Choice.h"
#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1X509GeneralNames;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1X509DistributionPointName : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1ASN1Choice > {
 @public
  id<LibOrgBouncycastleAsn1ASN1Encodable> name_;
  jint type_;
}
@property (readonly, class) jint FULL_NAME NS_SWIFT_NAME(FULL_NAME);
@property (readonly, class) jint NAME_RELATIVE_TO_CRL_ISSUER NS_SWIFT_NAME(NAME_RELATIVE_TO_CRL_ISSUER);

+ (jint)FULL_NAME;

+ (jint)NAME_RELATIVE_TO_CRL_ISSUER;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509GeneralNames:(LibOrgBouncycastleAsn1X509GeneralNames *)name;

- (instancetype __nonnull)initWithInt:(jint)type
withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)name;

+ (LibOrgBouncycastleAsn1X509DistributionPointName *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                               withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1X509DistributionPointName *)getInstanceWithId:(id)obj;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getName;

- (jint)getType;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509DistributionPointName)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509DistributionPointName, name_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

inline jint LibOrgBouncycastleAsn1X509DistributionPointName_get_FULL_NAME(void);
#define LibOrgBouncycastleAsn1X509DistributionPointName_FULL_NAME 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1X509DistributionPointName, FULL_NAME, jint)

inline jint LibOrgBouncycastleAsn1X509DistributionPointName_get_NAME_RELATIVE_TO_CRL_ISSUER(void);
#define LibOrgBouncycastleAsn1X509DistributionPointName_NAME_RELATIVE_TO_CRL_ISSUER 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1X509DistributionPointName, NAME_RELATIVE_TO_CRL_ISSUER, jint)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509DistributionPointName *LibOrgBouncycastleAsn1X509DistributionPointName_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509DistributionPointName *LibOrgBouncycastleAsn1X509DistributionPointName_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509DistributionPointName_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1X509DistributionPointName *self, jint type, id<LibOrgBouncycastleAsn1ASN1Encodable> name);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509DistributionPointName *new_LibOrgBouncycastleAsn1X509DistributionPointName_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(jint type, id<LibOrgBouncycastleAsn1ASN1Encodable> name) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509DistributionPointName *create_LibOrgBouncycastleAsn1X509DistributionPointName_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(jint type, id<LibOrgBouncycastleAsn1ASN1Encodable> name);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509DistributionPointName_initWithLibOrgBouncycastleAsn1X509GeneralNames_(LibOrgBouncycastleAsn1X509DistributionPointName *self, LibOrgBouncycastleAsn1X509GeneralNames *name);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509DistributionPointName *new_LibOrgBouncycastleAsn1X509DistributionPointName_initWithLibOrgBouncycastleAsn1X509GeneralNames_(LibOrgBouncycastleAsn1X509GeneralNames *name) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509DistributionPointName *create_LibOrgBouncycastleAsn1X509DistributionPointName_initWithLibOrgBouncycastleAsn1X509GeneralNames_(LibOrgBouncycastleAsn1X509GeneralNames *name);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509DistributionPointName_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1X509DistributionPointName *self, LibOrgBouncycastleAsn1ASN1TaggedObject *obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509DistributionPointName *new_LibOrgBouncycastleAsn1X509DistributionPointName_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509DistributionPointName *create_LibOrgBouncycastleAsn1X509DistributionPointName_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509DistributionPointName)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DistributionPointName_H
