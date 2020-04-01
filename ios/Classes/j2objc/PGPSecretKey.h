//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPSecretKey.java
//

#ifndef PGPSecretKey_H
#define PGPSecretKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaIoOutputStream;
@class LibOrgBouncycastleBcpgS2K;
@class LibOrgBouncycastleBcpgSecretKeyPacket;
@class LibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor;
@class LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor;
@class LibOrgBouncycastleOpenpgpPGPKeyPair;
@class LibOrgBouncycastleOpenpgpPGPPrivateKey;
@class LibOrgBouncycastleOpenpgpPGPPublicKey;
@class LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector;
@protocol JavaUtilIterator;
@protocol LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;
@protocol LibOrgBouncycastleOpenpgpOperatorPBEProtectionRemoverFactory;
@protocol LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder;
@protocol LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator;

@interface LibOrgBouncycastleOpenpgpPGPSecretKey : NSObject {
 @public
  LibOrgBouncycastleBcpgSecretKeyPacket *secret_;
  LibOrgBouncycastleOpenpgpPGPPublicKey *pub_;
}

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)certificationLevel
withLibOrgBouncycastleOpenpgpPGPKeyPair:(LibOrgBouncycastleOpenpgpPGPKeyPair *)keyPair
                         withNSString:(NSString *)id_
withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)checksumCalculator
withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector:(LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *)hashedPcks
withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector:(LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *)unhashedPcks
withLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder:(id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder>)certificationSignerBuilder
withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor:(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *)keyEncryptor;

- (instancetype __nonnull)initWithInt:(jint)certificationLevel
withLibOrgBouncycastleOpenpgpPGPKeyPair:(LibOrgBouncycastleOpenpgpPGPKeyPair *)keyPair
                         withNSString:(NSString *)id_
withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector:(LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *)hashedPcks
withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector:(LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *)unhashedPcks
withLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder:(id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder>)certificationSignerBuilder
withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor:(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *)keyEncryptor;

- (instancetype __nonnull)initWithLibOrgBouncycastleOpenpgpPGPPrivateKey:(LibOrgBouncycastleOpenpgpPGPPrivateKey *)privKey
                               withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey
                withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)checksumCalculator
                                                             withBoolean:(jboolean)isMasterKey
              withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor:(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *)keyEncryptor;

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgSecretKeyPacket:(LibOrgBouncycastleBcpgSecretKeyPacket *)secret
                              withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pub;

+ (LibOrgBouncycastleOpenpgpPGPSecretKey *)copyWithNewPasswordWithLibOrgBouncycastleOpenpgpPGPSecretKey:(LibOrgBouncycastleOpenpgpPGPSecretKey *)key
                                             withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor:(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor *)oldKeyDecryptor
                                             withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor:(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *)newKeyEncryptor OBJC_METHOD_FAMILY_NONE;

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)outStream;

- (LibOrgBouncycastleOpenpgpPGPPrivateKey *)extractPrivateKeyWithLibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor:(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor *)decryptorFactory;

- (IOSByteArray *)getEncoded;

- (jint)getKeyEncryptionAlgorithm;

- (jlong)getKeyID;

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKey;

- (LibOrgBouncycastleBcpgS2K *)getS2K;

- (jint)getS2KUsage;

- (id<JavaUtilIterator>)getUserAttributes;

- (id<JavaUtilIterator>)getUserIDs;

- (jboolean)isMasterKey;

- (jboolean)isPrivateKeyEmpty;

- (jboolean)isSigningKey;

+ (LibOrgBouncycastleOpenpgpPGPSecretKey *)parseSecretKeyFromSExprWithJavaIoInputStream:(JavaIoInputStream *)inputStream
                       withLibOrgBouncycastleOpenpgpOperatorPBEProtectionRemoverFactory:(id<LibOrgBouncycastleOpenpgpOperatorPBEProtectionRemoverFactory>)keyProtectionRemoverFactory
                          withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)fingerPrintCalculator;

+ (LibOrgBouncycastleOpenpgpPGPSecretKey *)parseSecretKeyFromSExprWithJavaIoInputStream:(JavaIoInputStream *)inputStream
                       withLibOrgBouncycastleOpenpgpOperatorPBEProtectionRemoverFactory:(id<LibOrgBouncycastleOpenpgpOperatorPBEProtectionRemoverFactory>)keyProtectionRemoverFactory
                                              withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey;

+ (LibOrgBouncycastleOpenpgpPGPSecretKey *)replacePublicKeyWithLibOrgBouncycastleOpenpgpPGPSecretKey:(LibOrgBouncycastleOpenpgpPGPSecretKey *)secretKey
                                                           withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)publicKey;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleOpenpgpPGPPrivateKey:(LibOrgBouncycastleOpenpgpPGPPrivateKey *)privKey
                               withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey
                withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)checksumCalculator
              withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor:(LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *)keyEncryptor;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpPGPSecretKey)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpPGPSecretKey, secret_, LibOrgBouncycastleBcpgSecretKeyPacket *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpPGPSecretKey, pub_, LibOrgBouncycastleOpenpgpPGPPublicKey *)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPSecretKey_initWithLibOrgBouncycastleBcpgSecretKeyPacket_withLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPSecretKey *self, LibOrgBouncycastleBcpgSecretKeyPacket *secret, LibOrgBouncycastleOpenpgpPGPPublicKey *pub);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *new_LibOrgBouncycastleOpenpgpPGPSecretKey_initWithLibOrgBouncycastleBcpgSecretKeyPacket_withLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleBcpgSecretKeyPacket *secret, LibOrgBouncycastleOpenpgpPGPPublicKey *pub) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *create_LibOrgBouncycastleOpenpgpPGPSecretKey_initWithLibOrgBouncycastleBcpgSecretKeyPacket_withLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleBcpgSecretKeyPacket *secret, LibOrgBouncycastleOpenpgpPGPPublicKey *pub);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPSecretKey_initWithLibOrgBouncycastleOpenpgpPGPPrivateKey_withLibOrgBouncycastleOpenpgpPGPPublicKey_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(LibOrgBouncycastleOpenpgpPGPSecretKey *self, LibOrgBouncycastleOpenpgpPGPPrivateKey *privKey, LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> checksumCalculator, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *keyEncryptor);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *new_LibOrgBouncycastleOpenpgpPGPSecretKey_initWithLibOrgBouncycastleOpenpgpPGPPrivateKey_withLibOrgBouncycastleOpenpgpPGPPublicKey_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(LibOrgBouncycastleOpenpgpPGPPrivateKey *privKey, LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> checksumCalculator, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *keyEncryptor) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *create_LibOrgBouncycastleOpenpgpPGPSecretKey_initWithLibOrgBouncycastleOpenpgpPGPPrivateKey_withLibOrgBouncycastleOpenpgpPGPPublicKey_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(LibOrgBouncycastleOpenpgpPGPPrivateKey *privKey, LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> checksumCalculator, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *keyEncryptor);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPSecretKey_initWithLibOrgBouncycastleOpenpgpPGPPrivateKey_withLibOrgBouncycastleOpenpgpPGPPublicKey_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withBoolean_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(LibOrgBouncycastleOpenpgpPGPSecretKey *self, LibOrgBouncycastleOpenpgpPGPPrivateKey *privKey, LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> checksumCalculator, jboolean isMasterKey, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *keyEncryptor);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *new_LibOrgBouncycastleOpenpgpPGPSecretKey_initWithLibOrgBouncycastleOpenpgpPGPPrivateKey_withLibOrgBouncycastleOpenpgpPGPPublicKey_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withBoolean_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(LibOrgBouncycastleOpenpgpPGPPrivateKey *privKey, LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> checksumCalculator, jboolean isMasterKey, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *keyEncryptor) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *create_LibOrgBouncycastleOpenpgpPGPSecretKey_initWithLibOrgBouncycastleOpenpgpPGPPrivateKey_withLibOrgBouncycastleOpenpgpPGPPublicKey_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withBoolean_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(LibOrgBouncycastleOpenpgpPGPPrivateKey *privKey, LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> checksumCalculator, jboolean isMasterKey, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *keyEncryptor);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPSecretKey_initWithInt_withLibOrgBouncycastleOpenpgpPGPKeyPair_withNSString_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(LibOrgBouncycastleOpenpgpPGPSecretKey *self, jint certificationLevel, LibOrgBouncycastleOpenpgpPGPKeyPair *keyPair, NSString *id_, LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *hashedPcks, LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *unhashedPcks, id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder> certificationSignerBuilder, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *keyEncryptor);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *new_LibOrgBouncycastleOpenpgpPGPSecretKey_initWithInt_withLibOrgBouncycastleOpenpgpPGPKeyPair_withNSString_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(jint certificationLevel, LibOrgBouncycastleOpenpgpPGPKeyPair *keyPair, NSString *id_, LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *hashedPcks, LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *unhashedPcks, id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder> certificationSignerBuilder, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *keyEncryptor) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *create_LibOrgBouncycastleOpenpgpPGPSecretKey_initWithInt_withLibOrgBouncycastleOpenpgpPGPKeyPair_withNSString_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(jint certificationLevel, LibOrgBouncycastleOpenpgpPGPKeyPair *keyPair, NSString *id_, LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *hashedPcks, LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *unhashedPcks, id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder> certificationSignerBuilder, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *keyEncryptor);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPSecretKey_initWithInt_withLibOrgBouncycastleOpenpgpPGPKeyPair_withNSString_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(LibOrgBouncycastleOpenpgpPGPSecretKey *self, jint certificationLevel, LibOrgBouncycastleOpenpgpPGPKeyPair *keyPair, NSString *id_, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> checksumCalculator, LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *hashedPcks, LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *unhashedPcks, id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder> certificationSignerBuilder, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *keyEncryptor);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *new_LibOrgBouncycastleOpenpgpPGPSecretKey_initWithInt_withLibOrgBouncycastleOpenpgpPGPKeyPair_withNSString_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(jint certificationLevel, LibOrgBouncycastleOpenpgpPGPKeyPair *keyPair, NSString *id_, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> checksumCalculator, LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *hashedPcks, LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *unhashedPcks, id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder> certificationSignerBuilder, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *keyEncryptor) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *create_LibOrgBouncycastleOpenpgpPGPSecretKey_initWithInt_withLibOrgBouncycastleOpenpgpPGPKeyPair_withNSString_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(jint certificationLevel, LibOrgBouncycastleOpenpgpPGPKeyPair *keyPair, NSString *id_, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> checksumCalculator, LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *hashedPcks, LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *unhashedPcks, id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder> certificationSignerBuilder, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *keyEncryptor);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *LibOrgBouncycastleOpenpgpPGPSecretKey_copyWithNewPasswordWithLibOrgBouncycastleOpenpgpPGPSecretKey_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(LibOrgBouncycastleOpenpgpPGPSecretKey *key, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor *oldKeyDecryptor, LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *newKeyEncryptor);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *LibOrgBouncycastleOpenpgpPGPSecretKey_replacePublicKeyWithLibOrgBouncycastleOpenpgpPGPSecretKey_withLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPSecretKey *secretKey, LibOrgBouncycastleOpenpgpPGPPublicKey *publicKey);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *LibOrgBouncycastleOpenpgpPGPSecretKey_parseSecretKeyFromSExprWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorPBEProtectionRemoverFactory_withLibOrgBouncycastleOpenpgpPGPPublicKey_(JavaIoInputStream *inputStream, id<LibOrgBouncycastleOpenpgpOperatorPBEProtectionRemoverFactory> keyProtectionRemoverFactory, LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKey *LibOrgBouncycastleOpenpgpPGPSecretKey_parseSecretKeyFromSExprWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorPBEProtectionRemoverFactory_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(JavaIoInputStream *inputStream, id<LibOrgBouncycastleOpenpgpOperatorPBEProtectionRemoverFactory> keyProtectionRemoverFactory, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpPGPSecretKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPSecretKey_H