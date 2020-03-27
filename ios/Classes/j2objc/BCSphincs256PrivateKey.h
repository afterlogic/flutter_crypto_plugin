//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/sphincs/BCSphincs256PrivateKey.java
//

#ifndef BCSphincs256PrivateKey_H
#define BCSphincs256PrivateKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "SPHINCSKey.h"
#include "java/security/PrivateKey.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1PkcsPrivateKeyInfo;
@class LibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey : NSObject < JavaSecurityPrivateKey, LibOrgBouncycastlePqcJcajceInterfacesSPHINCSKey >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)treeDigest
           withLibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters:(LibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters *)params;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)keyInfo;

- (jboolean)isEqual:(id)o;

- (NSString *)getAlgorithm;

- (IOSByteArray *)getEncoded;

- (NSString *)getFormat;

- (IOSByteArray *)getKeyData;

- (NSUInteger)hash;

#pragma mark Package-Private

- (id<LibOrgBouncycastleCryptoCipherParameters>)getKeyParams;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getTreeDigest;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters_(LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey *new_LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey *create_LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters *params);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey *self, LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *keyInfo);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey *new_LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *keyInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey *create_LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *keyInfo);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BCSphincs256PrivateKey_H
