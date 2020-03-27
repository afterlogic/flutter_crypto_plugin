//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/ExtensionsGenerator.java
//

#ifndef ExtensionsGenerator_H
#define ExtensionsGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1X509Extension;
@class LibOrgBouncycastleAsn1X509Extensions;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1X509ExtensionsGenerator : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (void)addExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                                       withBoolean:(jboolean)critical
                           withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)value;

- (void)addExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                                       withBoolean:(jboolean)critical
                                                     withByteArray:(IOSByteArray *)value;

- (void)addExtensionWithLibOrgBouncycastleAsn1X509Extension:(LibOrgBouncycastleAsn1X509Extension *)extension;

- (LibOrgBouncycastleAsn1X509Extensions *)generate;

- (jboolean)isEmpty;

- (void)reset;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509ExtensionsGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509ExtensionsGenerator_init(LibOrgBouncycastleAsn1X509ExtensionsGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509ExtensionsGenerator *new_LibOrgBouncycastleAsn1X509ExtensionsGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509ExtensionsGenerator *create_LibOrgBouncycastleAsn1X509ExtensionsGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509ExtensionsGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ExtensionsGenerator_H
