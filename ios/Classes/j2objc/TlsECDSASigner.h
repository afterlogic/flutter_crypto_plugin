//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsECDSASigner.java
//

#ifndef TlsECDSASigner_H
#define TlsECDSASigner_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "TlsDSASigner.h"

@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@protocol LibOrgBouncycastleCryptoDSA;

@interface LibOrgBouncycastleCryptoTlsTlsECDSASigner : LibOrgBouncycastleCryptoTlsTlsDSASigner

#pragma mark Public

- (instancetype __nonnull)init;

- (jboolean)isValidPublicKeyWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicKey;

#pragma mark Protected

- (id<LibOrgBouncycastleCryptoDSA>)createDSAImplWithShort:(jshort)hashAlgorithm;

- (jshort)getSignatureAlgorithm;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsTlsECDSASigner)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsECDSASigner_init(LibOrgBouncycastleCryptoTlsTlsECDSASigner *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsECDSASigner *new_LibOrgBouncycastleCryptoTlsTlsECDSASigner_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsECDSASigner *create_LibOrgBouncycastleCryptoTlsTlsECDSASigner_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsTlsECDSASigner)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TlsECDSASigner_H
