//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsSRPKeyExchange.java
//

#ifndef TlsSRPKeyExchange_H
#define TlsSRPKeyExchange_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AbstractTlsKeyExchange.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaIoOutputStream;
@class JavaMathBigInteger;
@class JavaUtilVector;
@class LibOrgBouncycastleCryptoAgreementSrpSRP6Client;
@class LibOrgBouncycastleCryptoAgreementSrpSRP6Server;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@class LibOrgBouncycastleCryptoParamsSRP6GroupParameters;
@class LibOrgBouncycastleCryptoTlsCertificate;
@class LibOrgBouncycastleCryptoTlsCertificateRequest;
@class LibOrgBouncycastleCryptoTlsSecurityParameters;
@class LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm;
@class LibOrgBouncycastleCryptoTlsTlsSRPLoginParameters;
@protocol LibOrgBouncycastleCryptoSigner;
@protocol LibOrgBouncycastleCryptoTlsTlsContext;
@protocol LibOrgBouncycastleCryptoTlsTlsCredentials;
@protocol LibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier;
@protocol LibOrgBouncycastleCryptoTlsTlsSigner;
@protocol LibOrgBouncycastleCryptoTlsTlsSignerCredentials;

@interface LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange : LibOrgBouncycastleCryptoTlsAbstractTlsKeyExchange {
 @public
  id<LibOrgBouncycastleCryptoTlsTlsSigner> tlsSigner_;
  id<LibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier> groupVerifier_;
  IOSByteArray *identity_;
  IOSByteArray *password_;
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *serverPublicKey_;
  LibOrgBouncycastleCryptoParamsSRP6GroupParameters *srpGroup_;
  LibOrgBouncycastleCryptoAgreementSrpSRP6Client *srpClient_;
  LibOrgBouncycastleCryptoAgreementSrpSRP6Server *srpServer_;
  JavaMathBigInteger *srpPeerCredentials_;
  JavaMathBigInteger *srpVerifier_;
  IOSByteArray *srpSalt_;
  id<LibOrgBouncycastleCryptoTlsTlsSignerCredentials> serverCredentials_;
}

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)keyExchange
                   withJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms
                        withByteArray:(IOSByteArray *)identity
                        withByteArray:(IOSByteArray *)password;

- (instancetype __nonnull)initWithInt:(jint)keyExchange
                   withJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms
                        withByteArray:(IOSByteArray *)identity
withLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters:(LibOrgBouncycastleCryptoTlsTlsSRPLoginParameters *)loginParameters;

- (instancetype __nonnull)initWithInt:(jint)keyExchange
                   withJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms
withLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier:(id<LibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier>)groupVerifier
                        withByteArray:(IOSByteArray *)identity
                        withByteArray:(IOSByteArray *)password;

- (void)generateClientKeyExchangeWithJavaIoOutputStream:(JavaIoOutputStream *)output;

- (IOSByteArray *)generatePremasterSecret;

- (IOSByteArray *)generateServerKeyExchange;

- (void)init__WithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context OBJC_METHOD_FAMILY_NONE;

- (void)processClientCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:(id<LibOrgBouncycastleCryptoTlsTlsCredentials>)clientCredentials;

- (void)processClientKeyExchangeWithJavaIoInputStream:(JavaIoInputStream *)input;

- (void)processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:(LibOrgBouncycastleCryptoTlsCertificate *)serverCertificate;

- (void)processServerCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:(id<LibOrgBouncycastleCryptoTlsTlsCredentials>)serverCredentials;

- (void)processServerKeyExchangeWithJavaIoInputStream:(JavaIoInputStream *)input;

- (jboolean)requiresServerKeyExchange;

- (void)skipServerCredentials;

- (void)validateCertificateRequestWithLibOrgBouncycastleCryptoTlsCertificateRequest:(LibOrgBouncycastleCryptoTlsCertificateRequest *)certificateRequest;

#pragma mark Protected

+ (id<LibOrgBouncycastleCryptoTlsTlsSigner>)createSignerWithInt:(jint)keyExchange;

- (id<LibOrgBouncycastleCryptoSigner>)initVerifyerWithLibOrgBouncycastleCryptoTlsTlsSigner:(id<LibOrgBouncycastleCryptoTlsTlsSigner>)tlsSigner
                                  withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:(LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                         withLibOrgBouncycastleCryptoTlsSecurityParameters:(LibOrgBouncycastleCryptoTlsSecurityParameters *)securityParameters OBJC_METHOD_FAMILY_NONE;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0
                   withJavaUtilVector:(JavaUtilVector *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, tlsSigner_, id<LibOrgBouncycastleCryptoTlsTlsSigner>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, groupVerifier_, id<LibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, identity_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, password_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, serverPublicKey_, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, srpGroup_, LibOrgBouncycastleCryptoParamsSRP6GroupParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, srpClient_, LibOrgBouncycastleCryptoAgreementSrpSRP6Client *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, srpServer_, LibOrgBouncycastleCryptoAgreementSrpSRP6Server *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, srpPeerCredentials_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, srpVerifier_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, srpSalt_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, serverCredentials_, id<LibOrgBouncycastleCryptoTlsTlsSignerCredentials>)

FOUNDATION_EXPORT id<LibOrgBouncycastleCryptoTlsTlsSigner> LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_createSignerWithInt_(jint keyExchange);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withByteArray_(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *self, jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSByteArray *identity, IOSByteArray *password);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *new_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withByteArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSByteArray *identity, IOSByteArray *password) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *create_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withByteArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSByteArray *identity, IOSByteArray *password);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier_withByteArray_withByteArray_(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *self, jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, id<LibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier> groupVerifier, IOSByteArray *identity, IOSByteArray *password);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *new_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier_withByteArray_withByteArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, id<LibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier> groupVerifier, IOSByteArray *identity, IOSByteArray *password) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *create_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier_withByteArray_withByteArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, id<LibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier> groupVerifier, IOSByteArray *identity, IOSByteArray *password);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters_(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *self, jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSByteArray *identity, LibOrgBouncycastleCryptoTlsTlsSRPLoginParameters *loginParameters);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *new_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSByteArray *identity, LibOrgBouncycastleCryptoTlsTlsSRPLoginParameters *loginParameters) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *create_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSByteArray *identity, LibOrgBouncycastleCryptoTlsTlsSRPLoginParameters *loginParameters);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TlsSRPKeyExchange_H
