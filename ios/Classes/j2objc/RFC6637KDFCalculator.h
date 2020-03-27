//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/RFC6637KDFCalculator.java
//

#ifndef RFC6637KDFCalculator_H
#define RFC6637KDFCalculator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleMathEcECPoint;
@protocol LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator;

@interface LibOrgBouncycastleOpenpgpOperatorRFC6637KDFCalculator : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)digCalc
                                                                               withInt:(jint)keyAlgorithm;

- (IOSByteArray *)createKeyWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)curveOID
                                      withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)s
                                                            withByteArray:(IOSByteArray *)recipientFingerPrint;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorRFC6637KDFCalculator)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorRFC6637KDFCalculator_initWithLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_(LibOrgBouncycastleOpenpgpOperatorRFC6637KDFCalculator *self, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> digCalc, jint keyAlgorithm);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorRFC6637KDFCalculator *new_LibOrgBouncycastleOpenpgpOperatorRFC6637KDFCalculator_initWithLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> digCalc, jint keyAlgorithm) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorRFC6637KDFCalculator *create_LibOrgBouncycastleOpenpgpOperatorRFC6637KDFCalculator_initWithLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> digCalc, jint keyAlgorithm);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorRFC6637KDFCalculator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RFC6637KDFCalculator_H
