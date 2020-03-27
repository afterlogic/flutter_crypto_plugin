//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DERExternalParser.java
//

#ifndef DERExternalParser_H
#define DERExternalParser_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Encodable.h"
#include "InMemoryRepresentable.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1StreamParser;

@interface LibOrgBouncycastleAsn1DERExternalParser : NSObject < LibOrgBouncycastleAsn1ASN1Encodable, LibOrgBouncycastleAsn1InMemoryRepresentable >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1StreamParser:(LibOrgBouncycastleAsn1ASN1StreamParser *)parser;

- (LibOrgBouncycastleAsn1ASN1Primitive *)getLoadedObject;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)readObject;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DERExternalParser)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DERExternalParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1DERExternalParser *self, LibOrgBouncycastleAsn1ASN1StreamParser *parser);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERExternalParser *new_LibOrgBouncycastleAsn1DERExternalParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ASN1StreamParser *parser) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERExternalParser *create_LibOrgBouncycastleAsn1DERExternalParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ASN1StreamParser *parser);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DERExternalParser)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DERExternalParser_H
