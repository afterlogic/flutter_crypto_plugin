//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/asn1/ParSet.java
//

#ifndef ParSet_H
#define ParSet_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSIntArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastlePqcAsn1ParSet : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)t
                         withIntArray:(IOSIntArray *)h
                         withIntArray:(IOSIntArray *)w
                         withIntArray:(IOSIntArray *)k;

- (IOSIntArray *)getH;

+ (LibOrgBouncycastlePqcAsn1ParSet *)getInstanceWithId:(id)o;

- (IOSIntArray *)getK;

- (jint)getT;

- (IOSIntArray *)getW;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastlePqcAsn1ParSet)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcAsn1ParSet_initWithInt_withIntArray_withIntArray_withIntArray_(LibOrgBouncycastlePqcAsn1ParSet *self, jint t, IOSIntArray *h, IOSIntArray *w, IOSIntArray *k);

FOUNDATION_EXPORT LibOrgBouncycastlePqcAsn1ParSet *new_LibOrgBouncycastlePqcAsn1ParSet_initWithInt_withIntArray_withIntArray_withIntArray_(jint t, IOSIntArray *h, IOSIntArray *w, IOSIntArray *k) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcAsn1ParSet *create_LibOrgBouncycastlePqcAsn1ParSet_initWithInt_withIntArray_withIntArray_withIntArray_(jint t, IOSIntArray *h, IOSIntArray *w, IOSIntArray *k);

FOUNDATION_EXPORT LibOrgBouncycastlePqcAsn1ParSet *LibOrgBouncycastlePqcAsn1ParSet_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcAsn1ParSet)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ParSet_H
