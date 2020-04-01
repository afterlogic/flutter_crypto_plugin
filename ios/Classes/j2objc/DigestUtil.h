//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/DigestUtil.java
//

#ifndef DigestUtil_H
#define DigestUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastlePqcCryptoXmssDigestUtil : NSObject

#pragma mark Public

+ (jint)getDigestSizeWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

#pragma mark Package-Private

- (instancetype __nonnull)init;

+ (id<LibOrgBouncycastleCryptoDigest>)getDigestWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getDigestOIDWithNSString:(NSString *)name;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastlePqcCryptoXmssDigestUtil)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoXmssDigestUtil_init(LibOrgBouncycastlePqcCryptoXmssDigestUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssDigestUtil *new_LibOrgBouncycastlePqcCryptoXmssDigestUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssDigestUtil *create_LibOrgBouncycastlePqcCryptoXmssDigestUtil_init(void);

FOUNDATION_EXPORT id<LibOrgBouncycastleCryptoDigest> LibOrgBouncycastlePqcCryptoXmssDigestUtil_getDigestWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastlePqcCryptoXmssDigestUtil_getDigestOIDWithNSString_(NSString *name);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoXmssDigestUtil_getDigestSizeWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoXmssDigestUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DigestUtil_H