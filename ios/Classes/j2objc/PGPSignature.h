//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPSignature.java
//

#ifndef PGPSignature_H
#define PGPSignature_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoOutputStream;
@class JavaUtilDate;
@class LibOrgBouncycastleBcpgBCPGInputStream;
@class LibOrgBouncycastleBcpgSignaturePacket;
@class LibOrgBouncycastleBcpgTrustPacket;
@class LibOrgBouncycastleOpenpgpPGPPublicKey;
@class LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector;
@class LibOrgBouncycastleOpenpgpPGPUserAttributeSubpacketVector;
@protocol LibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilderProvider;

@interface LibOrgBouncycastleOpenpgpPGPSignature : NSObject
@property (readonly, class) jint BINARY_DOCUMENT NS_SWIFT_NAME(BINARY_DOCUMENT);
@property (readonly, class) jint CANONICAL_TEXT_DOCUMENT NS_SWIFT_NAME(CANONICAL_TEXT_DOCUMENT);
@property (readonly, class) jint STAND_ALONE NS_SWIFT_NAME(STAND_ALONE);
@property (readonly, class) jint DEFAULT_CERTIFICATION NS_SWIFT_NAME(DEFAULT_CERTIFICATION);
@property (readonly, class) jint NO_CERTIFICATION NS_SWIFT_NAME(NO_CERTIFICATION);
@property (readonly, class) jint CASUAL_CERTIFICATION NS_SWIFT_NAME(CASUAL_CERTIFICATION);
@property (readonly, class) jint POSITIVE_CERTIFICATION NS_SWIFT_NAME(POSITIVE_CERTIFICATION);
@property (readonly, class) jint SUBKEY_BINDING NS_SWIFT_NAME(SUBKEY_BINDING);
@property (readonly, class) jint PRIMARYKEY_BINDING NS_SWIFT_NAME(PRIMARYKEY_BINDING);
@property (readonly, class) jint DIRECT_KEY NS_SWIFT_NAME(DIRECT_KEY);
@property (readonly, class) jint KEY_REVOCATION NS_SWIFT_NAME(KEY_REVOCATION);
@property (readonly, class) jint SUBKEY_REVOCATION NS_SWIFT_NAME(SUBKEY_REVOCATION);
@property (readonly, class) jint CERTIFICATION_REVOCATION NS_SWIFT_NAME(CERTIFICATION_REVOCATION);
@property (readonly, class) jint TIMESTAMP NS_SWIFT_NAME(TIMESTAMP);

+ (jint)BINARY_DOCUMENT;

+ (jint)CANONICAL_TEXT_DOCUMENT;

+ (jint)STAND_ALONE;

+ (jint)DEFAULT_CERTIFICATION;

+ (jint)NO_CERTIFICATION;

+ (jint)CASUAL_CERTIFICATION;

+ (jint)POSITIVE_CERTIFICATION;

+ (jint)SUBKEY_BINDING;

+ (jint)PRIMARYKEY_BINDING;

+ (jint)DIRECT_KEY;

+ (jint)KEY_REVOCATION;

+ (jint)SUBKEY_REVOCATION;

+ (jint)CERTIFICATION_REVOCATION;

+ (jint)TIMESTAMP;

#pragma mark Public

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)outStream;

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)outStream
                         withBoolean:(jboolean)forTransfer;

- (JavaUtilDate *)getCreationTime;

- (IOSByteArray *)getEncoded;

- (IOSByteArray *)getEncodedWithBoolean:(jboolean)forTransfer;

- (jint)getHashAlgorithm;

- (LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *)getHashedSubPackets;

- (jint)getKeyAlgorithm;

- (jlong)getKeyID;

- (IOSByteArray *)getSignature;

- (IOSByteArray *)getSignatureTrailer;

- (jint)getSignatureType;

- (LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *)getUnhashedSubPackets;

- (jint)getVersion;

- (jboolean)hasSubpackets;

- (void)init__WithLibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilderProvider:(id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilderProvider>)verifierBuilderProvider
                                           withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey OBJC_METHOD_FAMILY_NONE;

- (jboolean)isCertification;

+ (jboolean)isCertificationWithInt:(jint)signatureType;

- (void)updateWithByte:(jbyte)b;

- (void)updateWithByteArray:(IOSByteArray *)bytes;

- (void)updateWithByteArray:(IOSByteArray *)bytes
                    withInt:(jint)off
                    withInt:(jint)length;

- (jboolean)verify;

- (jboolean)verifyCertificationWithByteArray:(IOSByteArray *)rawID
   withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key;

- (jboolean)verifyCertificationWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey;

- (jboolean)verifyCertificationWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)masterKey
                               withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey;

- (jboolean)verifyCertificationWithLibOrgBouncycastleOpenpgpPGPUserAttributeSubpacketVector:(LibOrgBouncycastleOpenpgpPGPUserAttributeSubpacketVector *)userAttributes
                                                  withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key;

- (jboolean)verifyCertificationWithNSString:(NSString *)id_
  withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)pIn;

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgSignaturePacket:(LibOrgBouncycastleBcpgSignaturePacket *)sigPacket;

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgSignaturePacket:(LibOrgBouncycastleBcpgSignaturePacket *)sigPacket
                                  withLibOrgBouncycastleBcpgTrustPacket:(LibOrgBouncycastleBcpgTrustPacket *)trustPacket;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpPGPSignature)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_BINARY_DOCUMENT(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_BINARY_DOCUMENT 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, BINARY_DOCUMENT, jint)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_CANONICAL_TEXT_DOCUMENT(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_CANONICAL_TEXT_DOCUMENT 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, CANONICAL_TEXT_DOCUMENT, jint)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_STAND_ALONE(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_STAND_ALONE 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, STAND_ALONE, jint)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_DEFAULT_CERTIFICATION(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_DEFAULT_CERTIFICATION 16
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, DEFAULT_CERTIFICATION, jint)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_NO_CERTIFICATION(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_NO_CERTIFICATION 17
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, NO_CERTIFICATION, jint)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_CASUAL_CERTIFICATION(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_CASUAL_CERTIFICATION 18
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, CASUAL_CERTIFICATION, jint)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_POSITIVE_CERTIFICATION(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_POSITIVE_CERTIFICATION 19
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, POSITIVE_CERTIFICATION, jint)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_SUBKEY_BINDING(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_SUBKEY_BINDING 24
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, SUBKEY_BINDING, jint)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_PRIMARYKEY_BINDING(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_PRIMARYKEY_BINDING 25
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, PRIMARYKEY_BINDING, jint)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_DIRECT_KEY(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_DIRECT_KEY 31
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, DIRECT_KEY, jint)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_KEY_REVOCATION(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_KEY_REVOCATION 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, KEY_REVOCATION, jint)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_SUBKEY_REVOCATION(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_SUBKEY_REVOCATION 40
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, SUBKEY_REVOCATION, jint)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_CERTIFICATION_REVOCATION(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_CERTIFICATION_REVOCATION 48
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, CERTIFICATION_REVOCATION, jint)

inline jint LibOrgBouncycastleOpenpgpPGPSignature_get_TIMESTAMP(void);
#define LibOrgBouncycastleOpenpgpPGPSignature_TIMESTAMP 64
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPSignature, TIMESTAMP, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleOpenpgpPGPSignature *self, LibOrgBouncycastleBcpgBCPGInputStream *pIn);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSignature *new_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *pIn) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSignature *create_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *pIn);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_(LibOrgBouncycastleOpenpgpPGPSignature *self, LibOrgBouncycastleBcpgSignaturePacket *sigPacket);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSignature *new_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_(LibOrgBouncycastleBcpgSignaturePacket *sigPacket) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSignature *create_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_(LibOrgBouncycastleBcpgSignaturePacket *sigPacket);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_withLibOrgBouncycastleBcpgTrustPacket_(LibOrgBouncycastleOpenpgpPGPSignature *self, LibOrgBouncycastleBcpgSignaturePacket *sigPacket, LibOrgBouncycastleBcpgTrustPacket *trustPacket);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSignature *new_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_withLibOrgBouncycastleBcpgTrustPacket_(LibOrgBouncycastleBcpgSignaturePacket *sigPacket, LibOrgBouncycastleBcpgTrustPacket *trustPacket) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSignature *create_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_withLibOrgBouncycastleBcpgTrustPacket_(LibOrgBouncycastleBcpgSignaturePacket *sigPacket, LibOrgBouncycastleBcpgTrustPacket *trustPacket);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleOpenpgpPGPSignature_isCertificationWithInt_(jint signatureType);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpPGPSignature)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPSignature_H
