//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/spec/JcajceGOST3410ParameterSpec.java
//

#ifndef JcajceGOST3410ParameterSpec_H
#define JcajceGOST3410ParameterSpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;

@interface LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec : NSObject < JavaSecuritySpecAlgorithmParameterSpec >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)publicKeyParamSet
                              withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)digestParamSet;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)publicKeyParamSet
                              withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)digestParamSet
                              withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)encryptionParamSet;

- (instancetype __nonnull)initWithNSString:(NSString *)publicKeyParamSet;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getDigestParamSet;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getEncryptionParamSet;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getPublicKeyParamSet;

- (NSString *)getPublicKeyParamSetName;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithNSString_(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *self, NSString *publicKeyParamSet);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *new_LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithNSString_(NSString *publicKeyParamSet) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *create_LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithNSString_(NSString *publicKeyParamSet);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *new_LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *create_LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionParamSet);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *new_LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionParamSet) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec *create_LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionParamSet);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceSpecJcajceGOST3410ParameterSpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceGOST3410ParameterSpec_H
