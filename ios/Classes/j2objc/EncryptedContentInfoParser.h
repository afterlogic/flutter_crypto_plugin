//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/EncryptedContentInfoParser.java
//

#ifndef EncryptedContentInfoParser_H
#define EncryptedContentInfoParser_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;
@protocol LibOrgBouncycastleAsn1ASN1SequenceParser;

@interface LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1SequenceParser:(id<LibOrgBouncycastleAsn1ASN1SequenceParser>)seq;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getContentEncryptionAlgorithm;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getContentType;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getEncryptedContentWithInt:(jint)tag;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser *self, id<LibOrgBouncycastleAsn1ASN1SequenceParser> seq);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser *new_LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(id<LibOrgBouncycastleAsn1ASN1SequenceParser> seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser *create_LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(id<LibOrgBouncycastleAsn1ASN1SequenceParser> seq);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // EncryptedContentInfoParser_H
