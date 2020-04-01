//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1External.java
//

#ifndef ASN1External_H
#define ASN1External_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Primitive.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1EncodableVector;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1DERTaggedObject;

@interface LibOrgBouncycastleAsn1ASN1External : LibOrgBouncycastleAsn1ASN1Primitive {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *directReference_;
  LibOrgBouncycastleAsn1ASN1Integer *indirectReference_;
  LibOrgBouncycastleAsn1ASN1Primitive *dataValueDescriptor_;
  jint encoding_;
  LibOrgBouncycastleAsn1ASN1Primitive *externalContent_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)vector;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)directReference
                                       withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)indirectReference
                                     withLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)dataValueDescriptor
                                   withLibOrgBouncycastleAsn1DERTaggedObject:(LibOrgBouncycastleAsn1DERTaggedObject *)externalData;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)directReference
                                       withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)indirectReference
                                     withLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)dataValueDescriptor
                                                                     withInt:(jint)encoding
                                     withLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)externalData;

- (LibOrgBouncycastleAsn1ASN1Primitive *)getDataValueDescriptor;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getDirectReference;

- (jint)getEncoding;

- (LibOrgBouncycastleAsn1ASN1Primitive *)getExternalContent;

- (LibOrgBouncycastleAsn1ASN1Integer *)getIndirectReference;

- (NSUInteger)hash;

#pragma mark Package-Private

- (jboolean)asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)o;

- (jint)encodedLength;

- (jboolean)isConstructed;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toDERObject;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1ASN1External)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1ASN1External, directReference_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1ASN1External, indirectReference_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1ASN1External, dataValueDescriptor_, LibOrgBouncycastleAsn1ASN1Primitive *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1ASN1External, externalContent_, LibOrgBouncycastleAsn1ASN1Primitive *)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1External_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1ASN1External *self, LibOrgBouncycastleAsn1ASN1EncodableVector *vector);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1External_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Primitive_withLibOrgBouncycastleAsn1DERTaggedObject_(LibOrgBouncycastleAsn1ASN1External *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *directReference, LibOrgBouncycastleAsn1ASN1Integer *indirectReference, LibOrgBouncycastleAsn1ASN1Primitive *dataValueDescriptor, LibOrgBouncycastleAsn1DERTaggedObject *externalData);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1External_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Primitive_withInt_withLibOrgBouncycastleAsn1ASN1Primitive_(LibOrgBouncycastleAsn1ASN1External *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *directReference, LibOrgBouncycastleAsn1ASN1Integer *indirectReference, LibOrgBouncycastleAsn1ASN1Primitive *dataValueDescriptor, jint encoding, LibOrgBouncycastleAsn1ASN1Primitive *externalData);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1ASN1External)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ASN1External_H