//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/tsp/Accuracy.java
//

#ifndef Accuracy_H
#define Accuracy_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastleAsn1TspAccuracy : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *seconds_;
  LibOrgBouncycastleAsn1ASN1Integer *millis_;
  LibOrgBouncycastleAsn1ASN1Integer *micros_;
}
@property (readonly, class) jint MIN_MILLIS NS_SWIFT_NAME(MIN_MILLIS);
@property (readonly, class) jint MAX_MILLIS NS_SWIFT_NAME(MAX_MILLIS);
@property (readonly, class) jint MIN_MICROS NS_SWIFT_NAME(MIN_MICROS);
@property (readonly, class) jint MAX_MICROS NS_SWIFT_NAME(MAX_MICROS);

+ (jint)MIN_MILLIS;

+ (jint)MAX_MILLIS;

+ (jint)MIN_MICROS;

+ (jint)MAX_MICROS;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)seconds
                              withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)millis
                              withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)micros;

+ (LibOrgBouncycastleAsn1TspAccuracy *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Integer *)getMicros;

- (LibOrgBouncycastleAsn1ASN1Integer *)getMillis;

- (LibOrgBouncycastleAsn1ASN1Integer *)getSeconds;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

#pragma mark Protected

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1TspAccuracy)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspAccuracy, seconds_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspAccuracy, millis_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspAccuracy, micros_, LibOrgBouncycastleAsn1ASN1Integer *)

inline jint LibOrgBouncycastleAsn1TspAccuracy_get_MIN_MILLIS(void);
#define LibOrgBouncycastleAsn1TspAccuracy_MIN_MILLIS 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1TspAccuracy, MIN_MILLIS, jint)

inline jint LibOrgBouncycastleAsn1TspAccuracy_get_MAX_MILLIS(void);
#define LibOrgBouncycastleAsn1TspAccuracy_MAX_MILLIS 999
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1TspAccuracy, MAX_MILLIS, jint)

inline jint LibOrgBouncycastleAsn1TspAccuracy_get_MIN_MICROS(void);
#define LibOrgBouncycastleAsn1TspAccuracy_MIN_MICROS 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1TspAccuracy, MIN_MICROS, jint)

inline jint LibOrgBouncycastleAsn1TspAccuracy_get_MAX_MICROS(void);
#define LibOrgBouncycastleAsn1TspAccuracy_MAX_MICROS 999
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1TspAccuracy, MAX_MICROS, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1TspAccuracy_init(LibOrgBouncycastleAsn1TspAccuracy *self);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspAccuracy *new_LibOrgBouncycastleAsn1TspAccuracy_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspAccuracy *create_LibOrgBouncycastleAsn1TspAccuracy_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1TspAccuracy *self, LibOrgBouncycastleAsn1ASN1Integer *seconds, LibOrgBouncycastleAsn1ASN1Integer *millis, LibOrgBouncycastleAsn1ASN1Integer *micros);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspAccuracy *new_LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1ASN1Integer *seconds, LibOrgBouncycastleAsn1ASN1Integer *millis, LibOrgBouncycastleAsn1ASN1Integer *micros) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspAccuracy *create_LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1ASN1Integer *seconds, LibOrgBouncycastleAsn1ASN1Integer *millis, LibOrgBouncycastleAsn1ASN1Integer *micros);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspAccuracy *LibOrgBouncycastleAsn1TspAccuracy_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1TspAccuracy)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Accuracy_H
