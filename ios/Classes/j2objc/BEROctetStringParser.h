//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/BEROctetStringParser.java
//

#ifndef BEROctetStringParser_H
#define BEROctetStringParser_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1OctetStringParser.h"
#include "J2ObjC_header.h"

@class JavaIoInputStream;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1StreamParser;

@interface LibOrgBouncycastleAsn1BEROctetStringParser : NSObject < LibOrgBouncycastleAsn1ASN1OctetStringParser >

#pragma mark Public

- (LibOrgBouncycastleAsn1ASN1Primitive *)getLoadedObject;

- (JavaIoInputStream *)getOctetStream;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1StreamParser:(LibOrgBouncycastleAsn1ASN1StreamParser *)parser;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1BEROctetStringParser)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BEROctetStringParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1BEROctetStringParser *self, LibOrgBouncycastleAsn1ASN1StreamParser *parser);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BEROctetStringParser *new_LibOrgBouncycastleAsn1BEROctetStringParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ASN1StreamParser *parser) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BEROctetStringParser *create_LibOrgBouncycastleAsn1BEROctetStringParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ASN1StreamParser *parser);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1BEROctetStringParser)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BEROctetStringParser_H
