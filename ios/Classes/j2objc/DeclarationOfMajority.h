//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/isismtt/x509/DeclarationOfMajority.java
//

#ifndef DeclarationOfMajority_H
#define DeclarationOfMajority_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Choice.h"
#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1GeneralizedTime;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;

@interface LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1ASN1Choice >
@property (readonly, class) jint notYoungerThan_ NS_SWIFT_NAME(notYoungerThan_);
@property (readonly, class) jint fullAgeAtCountry_ NS_SWIFT_NAME(fullAgeAtCountry_);
@property (readonly, class) jint dateOfBirth NS_SWIFT_NAME(dateOfBirth);

+ (jint)notYoungerThan_;

+ (jint)fullAgeAtCountry_;

+ (jint)dateOfBirth;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)dateOfBirth;

- (instancetype __nonnull)initWithBoolean:(jboolean)fullAge
                             withNSString:(NSString *)country;

- (instancetype __nonnull)initWithInt:(jint)notYoungerThan;

- (LibOrgBouncycastleAsn1ASN1Sequence *)fullAgeAtCountry;

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getDateOfBirth;

+ (LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority *)getInstanceWithId:(id)obj;

- (jint)getType;

- (jint)notYoungerThan;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority)

inline jint LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_get_notYoungerThan_(void);
#define LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_notYoungerThan_ 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority, notYoungerThan_, jint)

inline jint LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_get_fullAgeAtCountry_(void);
#define LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_fullAgeAtCountry_ 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority, fullAgeAtCountry_, jint)

inline jint LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_get_dateOfBirth(void);
#define LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_dateOfBirth 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority, dateOfBirth, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_initWithInt_(LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority *self, jint notYoungerThan);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority *new_LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_initWithInt_(jint notYoungerThan) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority *create_LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_initWithInt_(jint notYoungerThan);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_initWithBoolean_withNSString_(LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority *self, jboolean fullAge, NSString *country);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority *new_LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_initWithBoolean_withNSString_(jboolean fullAge, NSString *country) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority *create_LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_initWithBoolean_withNSString_(jboolean fullAge, NSString *country);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority *self, LibOrgBouncycastleAsn1ASN1GeneralizedTime *dateOfBirth);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority *new_LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *dateOfBirth) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority *create_LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *dateOfBirth);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority *LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1IsismttX509DeclarationOfMajority)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DeclarationOfMajority_H
