//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/xmss/BCXMSSPrivateKey.java
//

#ifndef BCXMSSPrivateKey_H
#define BCXMSSPrivateKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "XMSSPrivateKey.h"
#include "java/security/PrivateKey.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1PkcsPrivateKeyInfo;
@class LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey : NSObject < JavaSecurityPrivateKey, LibOrgBouncycastlePqcJcajceInterfacesXMSSPrivateKey >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)treeDigest
                 withLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *)keyParams;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)keyInfo;

- (jboolean)isEqual:(id)o;

- (NSString *)getAlgorithm;

- (IOSByteArray *)getEncoded;

- (NSString *)getFormat;

- (jint)getHeight;

- (NSString *)getTreeDigest;

- (jlong)getUsagesRemaining;

- (NSUInteger)hash;

#pragma mark Package-Private

- (id<LibOrgBouncycastleCryptoCipherParameters>)getKeyParams;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getTreeDigestOID;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *keyParams);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey *new_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *keyParams) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey *create_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *keyParams);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey *self, LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *keyInfo);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey *new_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *keyInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey *create_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *keyInfo);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSPrivateKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BCXMSSPrivateKey_H