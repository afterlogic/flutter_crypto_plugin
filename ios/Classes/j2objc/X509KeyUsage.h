//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/X509KeyUsage.java
//

#ifndef X509KeyUsage_H
#define X509KeyUsage_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastleJceX509KeyUsage : LibOrgBouncycastleAsn1ASN1Object
@property (readonly, class) jint digitalSignature NS_SWIFT_NAME(digitalSignature);
@property (readonly, class) jint nonRepudiation NS_SWIFT_NAME(nonRepudiation);
@property (readonly, class) jint keyEncipherment NS_SWIFT_NAME(keyEncipherment);
@property (readonly, class) jint dataEncipherment NS_SWIFT_NAME(dataEncipherment);
@property (readonly, class) jint keyAgreement NS_SWIFT_NAME(keyAgreement);
@property (readonly, class) jint keyCertSign NS_SWIFT_NAME(keyCertSign);
@property (readonly, class) jint cRLSign NS_SWIFT_NAME(cRLSign);
@property (readonly, class) jint encipherOnly NS_SWIFT_NAME(encipherOnly);
@property (readonly, class) jint decipherOnly NS_SWIFT_NAME(decipherOnly);

+ (jint)digitalSignature;

+ (jint)nonRepudiation;

+ (jint)keyEncipherment;

+ (jint)dataEncipherment;

+ (jint)keyAgreement;

+ (jint)keyCertSign;

+ (jint)cRLSign;

+ (jint)encipherOnly;

+ (jint)decipherOnly;

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)usage;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceX509KeyUsage)

inline jint LibOrgBouncycastleJceX509KeyUsage_get_digitalSignature(void);
#define LibOrgBouncycastleJceX509KeyUsage_digitalSignature 128
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJceX509KeyUsage, digitalSignature, jint)

inline jint LibOrgBouncycastleJceX509KeyUsage_get_nonRepudiation(void);
#define LibOrgBouncycastleJceX509KeyUsage_nonRepudiation 64
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJceX509KeyUsage, nonRepudiation, jint)

inline jint LibOrgBouncycastleJceX509KeyUsage_get_keyEncipherment(void);
#define LibOrgBouncycastleJceX509KeyUsage_keyEncipherment 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJceX509KeyUsage, keyEncipherment, jint)

inline jint LibOrgBouncycastleJceX509KeyUsage_get_dataEncipherment(void);
#define LibOrgBouncycastleJceX509KeyUsage_dataEncipherment 16
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJceX509KeyUsage, dataEncipherment, jint)

inline jint LibOrgBouncycastleJceX509KeyUsage_get_keyAgreement(void);
#define LibOrgBouncycastleJceX509KeyUsage_keyAgreement 8
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJceX509KeyUsage, keyAgreement, jint)

inline jint LibOrgBouncycastleJceX509KeyUsage_get_keyCertSign(void);
#define LibOrgBouncycastleJceX509KeyUsage_keyCertSign 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJceX509KeyUsage, keyCertSign, jint)

inline jint LibOrgBouncycastleJceX509KeyUsage_get_cRLSign(void);
#define LibOrgBouncycastleJceX509KeyUsage_cRLSign 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJceX509KeyUsage, cRLSign, jint)

inline jint LibOrgBouncycastleJceX509KeyUsage_get_encipherOnly(void);
#define LibOrgBouncycastleJceX509KeyUsage_encipherOnly 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJceX509KeyUsage, encipherOnly, jint)

inline jint LibOrgBouncycastleJceX509KeyUsage_get_decipherOnly(void);
#define LibOrgBouncycastleJceX509KeyUsage_decipherOnly 32768
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJceX509KeyUsage, decipherOnly, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleJceX509KeyUsage_initWithInt_(LibOrgBouncycastleJceX509KeyUsage *self, jint usage);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509KeyUsage *new_LibOrgBouncycastleJceX509KeyUsage_initWithInt_(jint usage) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceX509KeyUsage *create_LibOrgBouncycastleJceX509KeyUsage_initWithInt_(jint usage);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceX509KeyUsage)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509KeyUsage_H