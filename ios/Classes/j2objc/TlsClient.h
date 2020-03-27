//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsClient.java
//

#ifndef TlsClient_H
#define TlsClient_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "TlsPeer.h"

@class IOSByteArray;
@class IOSIntArray;
@class IOSShortArray;
@class JavaUtilHashtable;
@class JavaUtilVector;
@class LibOrgBouncycastleCryptoTlsNewSessionTicket;
@class LibOrgBouncycastleCryptoTlsProtocolVersion;
@protocol LibOrgBouncycastleCryptoTlsTlsAuthentication;
@protocol LibOrgBouncycastleCryptoTlsTlsClientContext;
@protocol LibOrgBouncycastleCryptoTlsTlsKeyExchange;
@protocol LibOrgBouncycastleCryptoTlsTlsSession;

@protocol LibOrgBouncycastleCryptoTlsTlsClient < LibOrgBouncycastleCryptoTlsTlsPeer, JavaObject >

- (void)init__WithLibOrgBouncycastleCryptoTlsTlsClientContext:(id<LibOrgBouncycastleCryptoTlsTlsClientContext>)context OBJC_METHOD_FAMILY_NONE;

- (id<LibOrgBouncycastleCryptoTlsTlsSession>)getSessionToResume;

- (LibOrgBouncycastleCryptoTlsProtocolVersion *)getClientHelloRecordLayerVersion;

- (LibOrgBouncycastleCryptoTlsProtocolVersion *)getClientVersion;

- (jboolean)isFallback;

- (IOSIntArray *)getCipherSuites;

- (IOSShortArray *)getCompressionMethods;

- (JavaUtilHashtable *)getClientExtensions;

- (void)notifyServerVersionWithLibOrgBouncycastleCryptoTlsProtocolVersion:(LibOrgBouncycastleCryptoTlsProtocolVersion *)selectedVersion;

- (void)notifySessionIDWithByteArray:(IOSByteArray *)sessionID;

- (void)notifySelectedCipherSuiteWithInt:(jint)selectedCipherSuite;

- (void)notifySelectedCompressionMethodWithShort:(jshort)selectedCompressionMethod;

- (void)processServerExtensionsWithJavaUtilHashtable:(JavaUtilHashtable *)serverExtensions;

- (void)processServerSupplementalDataWithJavaUtilVector:(JavaUtilVector *)serverSupplementalData;

- (id<LibOrgBouncycastleCryptoTlsTlsKeyExchange>)getKeyExchange;

- (id<LibOrgBouncycastleCryptoTlsTlsAuthentication>)getAuthentication;

- (JavaUtilVector *)getClientSupplementalData;

- (void)notifyNewSessionTicketWithLibOrgBouncycastleCryptoTlsNewSessionTicket:(LibOrgBouncycastleCryptoTlsNewSessionTicket *)newSessionTicket;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsTlsClient)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsTlsClient)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TlsClient_H