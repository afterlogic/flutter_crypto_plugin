//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/AbstractTlsSignerCredentials.java
//

#ifndef AbstractTlsSignerCredentials_H
#define AbstractTlsSignerCredentials_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AbstractTlsCredentials.h"
#include "J2ObjC_header.h"
#include "TlsSignerCredentials.h"

@class LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm;

@interface LibOrgBouncycastleCryptoTlsAbstractTlsSignerCredentials : LibOrgBouncycastleCryptoTlsAbstractTlsCredentials < LibOrgBouncycastleCryptoTlsTlsSignerCredentials >

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *)getSignatureAndHashAlgorithm;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsAbstractTlsSignerCredentials)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsAbstractTlsSignerCredentials_init(LibOrgBouncycastleCryptoTlsAbstractTlsSignerCredentials *self);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsAbstractTlsSignerCredentials)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // AbstractTlsSignerCredentials_H