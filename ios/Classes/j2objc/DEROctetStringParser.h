//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DEROctetStringParser.java
//

#ifndef DEROctetStringParser_H
#define DEROctetStringParser_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1OctetStringParser.h"
#include "J2ObjC_header.h"

@class JavaIoInputStream;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1DefiniteLengthInputStream;

@interface LibOrgBouncycastleAsn1DEROctetStringParser : NSObject < LibOrgBouncycastleAsn1ASN1OctetStringParser >

#pragma mark Public

- (LibOrgBouncycastleAsn1ASN1Primitive *)getLoadedObject;

- (JavaIoInputStream *)getOctetStream;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1DefiniteLengthInputStream:(LibOrgBouncycastleAsn1DefiniteLengthInputStream *)stream;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DEROctetStringParser)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DEROctetStringParser_initWithLibOrgBouncycastleAsn1DefiniteLengthInputStream_(LibOrgBouncycastleAsn1DEROctetStringParser *self, LibOrgBouncycastleAsn1DefiniteLengthInputStream *stream);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DEROctetStringParser *new_LibOrgBouncycastleAsn1DEROctetStringParser_initWithLibOrgBouncycastleAsn1DefiniteLengthInputStream_(LibOrgBouncycastleAsn1DefiniteLengthInputStream *stream) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DEROctetStringParser *create_LibOrgBouncycastleAsn1DEROctetStringParser_initWithLibOrgBouncycastleAsn1DefiniteLengthInputStream_(LibOrgBouncycastleAsn1DefiniteLengthInputStream *stream);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DEROctetStringParser)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DEROctetStringParser_H
