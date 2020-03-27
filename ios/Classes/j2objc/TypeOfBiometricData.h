//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/qualified/TypeOfBiometricData.java
//

#ifndef TypeOfBiometricData_H
#define TypeOfBiometricData_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Choice.h"
#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1ASN1Choice > {
 @public
  id<LibOrgBouncycastleAsn1ASN1Encodable> obj_;
}
@property (readonly, class) jint PICTURE NS_SWIFT_NAME(PICTURE);
@property (readonly, class) jint HANDWRITTEN_SIGNATURE NS_SWIFT_NAME(HANDWRITTEN_SIGNATURE);

+ (jint)PICTURE;

+ (jint)HANDWRITTEN_SIGNATURE;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)BiometricDataID;

- (instancetype __nonnull)initWithInt:(jint)predefinedBiometricType;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getBiometricDataOid;

+ (LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData *)getInstanceWithId:(id)obj;

- (jint)getPredefinedBiometricType;

- (jboolean)isPredefined;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData, obj_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

inline jint LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData_get_PICTURE(void);
#define LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData_PICTURE 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData, PICTURE, jint)

inline jint LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData_get_HANDWRITTEN_SIGNATURE(void);
#define LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData_HANDWRITTEN_SIGNATURE 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData, HANDWRITTEN_SIGNATURE, jint)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData *LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData_initWithInt_(LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData *self, jint predefinedBiometricType);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData *new_LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData_initWithInt_(jint predefinedBiometricType) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData *create_LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData_initWithInt_(jint predefinedBiometricType);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *BiometricDataID);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData *new_LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *BiometricDataID) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData *create_LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *BiometricDataID);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509QualifiedTypeOfBiometricData)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TypeOfBiometricData_H
