//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DLOutputStream.java
//

#ifndef DLOutputStream_H
#define DLOutputStream_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1OutputStream.h"
#include "J2ObjC_header.h"

@class JavaIoOutputStream;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1DLOutputStream : LibOrgBouncycastleAsn1ASN1OutputStream

#pragma mark Public

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)os;

- (void)writeObjectWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DLOutputStream)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DLOutputStream_initWithJavaIoOutputStream_(LibOrgBouncycastleAsn1DLOutputStream *self, JavaIoOutputStream *os);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DLOutputStream *new_LibOrgBouncycastleAsn1DLOutputStream_initWithJavaIoOutputStream_(JavaIoOutputStream *os) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DLOutputStream *create_LibOrgBouncycastleAsn1DLOutputStream_initWithJavaIoOutputStream_(JavaIoOutputStream *os);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DLOutputStream)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DLOutputStream_H