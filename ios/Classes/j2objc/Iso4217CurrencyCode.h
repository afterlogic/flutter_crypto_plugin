//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/qualified/Iso4217CurrencyCode.java
//

#ifndef Iso4217CurrencyCode_H
#define Iso4217CurrencyCode_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Choice.h"
#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1ASN1Choice > {
 @public
  id<LibOrgBouncycastleAsn1ASN1Encodable> obj_;
  jint numeric_;
}

+ (jint)ALPHABETIC_MAXSIZE;

+ (jint)NUMERIC_MINSIZE;

+ (jint)NUMERIC_MAXSIZE;

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)numeric;

- (instancetype __nonnull)initWithNSString:(NSString *)alphabetic;

- (NSString *)getAlphabetic;

+ (LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode *)getInstanceWithId:(id)obj;

- (jint)getNumeric;

- (jboolean)isAlphabetic;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode, obj_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

inline jint LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode_get_ALPHABETIC_MAXSIZE(void);
#define LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode_ALPHABETIC_MAXSIZE 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode, ALPHABETIC_MAXSIZE, jint)

inline jint LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode_get_NUMERIC_MINSIZE(void);
#define LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode_NUMERIC_MINSIZE 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode, NUMERIC_MINSIZE, jint)

inline jint LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode_get_NUMERIC_MAXSIZE(void);
#define LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode_NUMERIC_MAXSIZE 999
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode, NUMERIC_MAXSIZE, jint)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode *LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode_initWithInt_(LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode *self, jint numeric);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode *new_LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode_initWithInt_(jint numeric) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode *create_LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode_initWithInt_(jint numeric);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode_initWithNSString_(LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode *self, NSString *alphabetic);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode *new_LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode_initWithNSString_(NSString *alphabetic) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode *create_LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode_initWithNSString_(NSString *alphabetic);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509QualifiedIso4217CurrencyCode)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Iso4217CurrencyCode_H
