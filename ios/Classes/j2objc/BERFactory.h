//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/BERFactory.java
//

#ifndef BERFactory_H
#define BERFactory_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1EncodableVector;
@class LibOrgBouncycastleAsn1BERSequence;
@class LibOrgBouncycastleAsn1BERSet;

@interface LibOrgBouncycastleAsn1BERFactory : NSObject
@property (readonly, class) LibOrgBouncycastleAsn1BERSequence *EMPTY_SEQUENCE NS_SWIFT_NAME(EMPTY_SEQUENCE);
@property (readonly, class) LibOrgBouncycastleAsn1BERSet *EMPTY_SET NS_SWIFT_NAME(EMPTY_SET);

+ (LibOrgBouncycastleAsn1BERSequence *)EMPTY_SEQUENCE;

+ (LibOrgBouncycastleAsn1BERSet *)EMPTY_SET;

#pragma mark Package-Private

- (instancetype __nonnull)init;

+ (LibOrgBouncycastleAsn1BERSequence *)createSequenceWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v;

+ (LibOrgBouncycastleAsn1BERSet *)createSetWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleAsn1BERFactory)

inline LibOrgBouncycastleAsn1BERSequence *LibOrgBouncycastleAsn1BERFactory_get_EMPTY_SEQUENCE(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERSequence *LibOrgBouncycastleAsn1BERFactory_EMPTY_SEQUENCE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1BERFactory, EMPTY_SEQUENCE, LibOrgBouncycastleAsn1BERSequence *)

inline LibOrgBouncycastleAsn1BERSet *LibOrgBouncycastleAsn1BERFactory_get_EMPTY_SET(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERSet *LibOrgBouncycastleAsn1BERFactory_EMPTY_SET;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1BERFactory, EMPTY_SET, LibOrgBouncycastleAsn1BERSet *)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BERFactory_init(LibOrgBouncycastleAsn1BERFactory *self);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERFactory *new_LibOrgBouncycastleAsn1BERFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERFactory *create_LibOrgBouncycastleAsn1BERFactory_init(void);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERSequence *LibOrgBouncycastleAsn1BERFactory_createSequenceWithLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1ASN1EncodableVector *v);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERSet *LibOrgBouncycastleAsn1BERFactory_createSetWithLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1ASN1EncodableVector *v);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1BERFactory)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BERFactory_H
