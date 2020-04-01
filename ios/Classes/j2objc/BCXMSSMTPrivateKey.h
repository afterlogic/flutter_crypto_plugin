//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/xmss/BCXMSSMTPrivateKey.java
//

#ifndef BCXMSSMTPrivateKey_H
#define BCXMSSMTPrivateKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "XMSSMTPrivateKey.h"
#include "java/security/PrivateKey.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1PkcsPrivateKeyInfo;
@class LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey : NSObject < JavaSecurityPrivateKey, LibOrgBouncycastlePqcJcajceInterfacesXMSSMTPrivateKey >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)treeDigest
               withLibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *)keyParams;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)keyInfo;

- (jboolean)isEqual:(id)o;

- (NSString *)getAlgorithm;

- (IOSByteArray *)getEncoded;

- (NSString *)getFormat;

- (jint)getHeight;

- (jint)getLayers;

- (NSString *)getTreeDigest;

- (jlong)getUsagesRemaining;

- (NSUInteger)hash;

#pragma mark Package-Private

- (id<LibOrgBouncycastleCryptoCipherParameters>)getKeyParams;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getTreeDigestOID;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *keyParams);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey *new_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *keyParams) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey *create_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *keyParams);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey *self, LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *keyInfo);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey *new_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *keyInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey *create_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *keyInfo);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPrivateKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BCXMSSMTPrivateKey_H