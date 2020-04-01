//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/DSAParameter.java
//

#ifndef DSAParameter_H
#define DSAParameter_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;

@interface LibOrgBouncycastleAsn1X509DSAParameter : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *p_;
  LibOrgBouncycastleAsn1ASN1Integer *q_;
  LibOrgBouncycastleAsn1ASN1Integer *g_;
}

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                              withJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)g;

- (JavaMathBigInteger *)getG;

+ (LibOrgBouncycastleAsn1X509DSAParameter *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1X509DSAParameter *)getInstanceWithId:(id)obj;

- (JavaMathBigInteger *)getP;

- (JavaMathBigInteger *)getQ;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509DSAParameter)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509DSAParameter, p_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509DSAParameter, q_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509DSAParameter, g_, LibOrgBouncycastleAsn1ASN1Integer *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509DSAParameter *LibOrgBouncycastleAsn1X509DSAParameter_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509DSAParameter *LibOrgBouncycastleAsn1X509DSAParameter_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509DSAParameter_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X509DSAParameter *self, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509DSAParameter *new_LibOrgBouncycastleAsn1X509DSAParameter_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509DSAParameter *create_LibOrgBouncycastleAsn1X509DSAParameter_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509DSAParameter)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DSAParameter_H