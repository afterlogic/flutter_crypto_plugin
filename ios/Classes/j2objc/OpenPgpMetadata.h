//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/decryption_verification/OpenPgpMetadata.java
//

#ifndef OpenPgpMetadata_H
#define OpenPgpMetadata_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaLangLong;
@class LibComAfterlogicPgpAlgorithmCompressionAlgorithm;
@class LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm;
@class LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder;
@class LibComAfterlogicPgpKeyOpenPgpV4Fingerprint;
@class LibOrgBouncycastleOpenpgpPGPPublicKeyRing;
@protocol JavaUtilSet;

@interface LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithJavaUtilSet:(id<JavaUtilSet>)recipientKeyIds
withLibComAfterlogicPgpKeyOpenPgpV4Fingerprint:(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *)decryptionFingerprint
withLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm:(LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *)symmetricKeyAlgorithm
withLibComAfterlogicPgpAlgorithmCompressionAlgorithm:(LibComAfterlogicPgpAlgorithmCompressionAlgorithm *)algorithm
                                  withBoolean:(jboolean)integrityProtected
                              withJavaUtilSet:(id<JavaUtilSet>)unverifiedSignatureKeyIds
                              withJavaUtilSet:(id<JavaUtilSet>)verifiedSignaturesFingerprints;

- (jboolean)containsVerifiedSignatureFromWithLibComAfterlogicPgpKeyOpenPgpV4Fingerprint:(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *)fingerprint;

- (jboolean)containsVerifiedSignatureFromWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)publicKeys;

- (id<JavaUtilSet>)getAllSignatureKeyFingerprints;

- (LibComAfterlogicPgpAlgorithmCompressionAlgorithm *)getCompressionAlgorithm;

- (LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *)getDecryptionFingerprint;

- (id<JavaUtilSet>)getRecipientKeyIds;

- (LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *)getSymmetricKeyAlgorithm;

- (id<JavaUtilSet>)getVerifiedSignaturesFingerprints;

- (jboolean)isEncrypted;

- (jboolean)isIntegrityProtected;

- (jboolean)isSigned;

- (jboolean)isVerified;

#pragma mark Package-Private

+ (LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *)getBuilder;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata)

FOUNDATION_EXPORT void LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_initWithJavaUtilSet_withLibComAfterlogicPgpKeyOpenPgpV4Fingerprint_withLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm_withLibComAfterlogicPgpAlgorithmCompressionAlgorithm_withBoolean_withJavaUtilSet_withJavaUtilSet_(LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata *self, id<JavaUtilSet> recipientKeyIds, LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *decryptionFingerprint, LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *symmetricKeyAlgorithm, LibComAfterlogicPgpAlgorithmCompressionAlgorithm *algorithm, jboolean integrityProtected, id<JavaUtilSet> unverifiedSignatureKeyIds, id<JavaUtilSet> verifiedSignaturesFingerprints);

FOUNDATION_EXPORT LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata *new_LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_initWithJavaUtilSet_withLibComAfterlogicPgpKeyOpenPgpV4Fingerprint_withLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm_withLibComAfterlogicPgpAlgorithmCompressionAlgorithm_withBoolean_withJavaUtilSet_withJavaUtilSet_(id<JavaUtilSet> recipientKeyIds, LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *decryptionFingerprint, LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *symmetricKeyAlgorithm, LibComAfterlogicPgpAlgorithmCompressionAlgorithm *algorithm, jboolean integrityProtected, id<JavaUtilSet> unverifiedSignatureKeyIds, id<JavaUtilSet> verifiedSignaturesFingerprints) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata *create_LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_initWithJavaUtilSet_withLibComAfterlogicPgpKeyOpenPgpV4Fingerprint_withLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm_withLibComAfterlogicPgpAlgorithmCompressionAlgorithm_withBoolean_withJavaUtilSet_withJavaUtilSet_(id<JavaUtilSet> recipientKeyIds, LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *decryptionFingerprint, LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *symmetricKeyAlgorithm, LibComAfterlogicPgpAlgorithmCompressionAlgorithm *algorithm, jboolean integrityProtected, id<JavaUtilSet> unverifiedSignatureKeyIds, id<JavaUtilSet> verifiedSignaturesFingerprints);

FOUNDATION_EXPORT LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_getBuilder(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata)

@interface LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder : NSObject

#pragma mark Public

- (LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *)addRecipientKeyIdWithJavaLangLong:(JavaLangLong *)keyId;

- (LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *)addUnverifiedSignatureKeyIdWithJavaLangLong:(JavaLangLong *)keyId;

- (LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *)addVerifiedSignatureFingerprintWithLibComAfterlogicPgpKeyOpenPgpV4Fingerprint:(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *)fingerprint;

- (LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata *)build;

- (LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *)setCompressionAlgorithmWithLibComAfterlogicPgpAlgorithmCompressionAlgorithm:(LibComAfterlogicPgpAlgorithmCompressionAlgorithm *)algorithm;

- (LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *)setDecryptionFingerprintWithLibComAfterlogicPgpKeyOpenPgpV4Fingerprint:(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *)fingerprint;

- (LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *)setIntegrityProtectedWithBoolean:(jboolean)integrityProtected;

- (LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *)setSymmetricKeyAlgorithmWithLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm:(LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *)symmetricKeyAlgorithm;

#pragma mark Package-Private

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder)

FOUNDATION_EXPORT void LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder_init(LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *self);

FOUNDATION_EXPORT LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *new_LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *create_LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // OpenPgpMetadata_H
