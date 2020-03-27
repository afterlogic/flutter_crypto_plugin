//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPSignature.java
//

#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "BCPGInputStream.h"
#include "BCPGOutputStream.h"
#include "BigIntegers.h"
#include "DERSequence.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "MPInteger.h"
#include "PGPContentVerifier.h"
#include "PGPContentVerifierBuilder.h"
#include "PGPContentVerifierBuilderProvider.h"
#include "PGPException.h"
#include "PGPPublicKey.h"
#include "PGPRuntimeOperationException.h"
#include "PGPSignature.h"
#include "PGPSignatureSubpacketVector.h"
#include "PGPUserAttributeSubpacketVector.h"
#include "Packet.h"
#include "PublicKeyPacket.h"
#include "SignaturePacket.h"
#include "Strings.h"
#include "TrustPacket.h"
#include "UserAttributeSubpacket.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/IOException.h"
#include "java/io/OutputStream.h"
#include "java/math/BigInteger.h"
#include "java/util/Date.h"

@interface LibOrgBouncycastleOpenpgpPGPSignature () {
 @public
  LibOrgBouncycastleBcpgSignaturePacket *sigPck_;
  jint signatureType_;
  LibOrgBouncycastleBcpgTrustPacket *trustPck_;
  id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifier> verifier_;
  jbyte lastb_;
  JavaIoOutputStream *sigOut_;
}

- (void)byteUpdateWithByte:(jbyte)b;

- (void)blockUpdateWithByteArray:(IOSByteArray *)block
                         withInt:(jint)off
                         withInt:(jint)len;

- (void)updateWithIdDataWithInt:(jint)header
                  withByteArray:(IOSByteArray *)idBytes;

- (void)updateWithPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key;

- (void)addTrailer;

- (LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *)createSubpacketVectorWithLibOrgBouncycastleBcpgSignatureSubpacketArray:(IOSObjectArray *)pcks;

- (IOSByteArray *)getEncodedPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpPGPSignature, sigPck_, LibOrgBouncycastleBcpgSignaturePacket *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpPGPSignature, trustPck_, LibOrgBouncycastleBcpgTrustPacket *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpPGPSignature, verifier_, id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifier>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpPGPSignature, sigOut_, JavaIoOutputStream *)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpPGPSignature_byteUpdateWithByte_(LibOrgBouncycastleOpenpgpPGPSignature *self, jbyte b);

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpPGPSignature_blockUpdateWithByteArray_withInt_withInt_(LibOrgBouncycastleOpenpgpPGPSignature *self, IOSByteArray *block, jint off, jint len);

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpPGPSignature_updateWithIdDataWithInt_withByteArray_(LibOrgBouncycastleOpenpgpPGPSignature *self, jint header, IOSByteArray *idBytes);

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpPGPSignature_updateWithPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPSignature *self, LibOrgBouncycastleOpenpgpPGPPublicKey *key);

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpPGPSignature_addTrailer(LibOrgBouncycastleOpenpgpPGPSignature *self);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *LibOrgBouncycastleOpenpgpPGPSignature_createSubpacketVectorWithLibOrgBouncycastleBcpgSignatureSubpacketArray_(LibOrgBouncycastleOpenpgpPGPSignature *self, IOSObjectArray *pcks);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleOpenpgpPGPSignature_getEncodedPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPSignature *self, LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey);

@implementation LibOrgBouncycastleOpenpgpPGPSignature

+ (jint)BINARY_DOCUMENT {
  return LibOrgBouncycastleOpenpgpPGPSignature_BINARY_DOCUMENT;
}

+ (jint)CANONICAL_TEXT_DOCUMENT {
  return LibOrgBouncycastleOpenpgpPGPSignature_CANONICAL_TEXT_DOCUMENT;
}

+ (jint)STAND_ALONE {
  return LibOrgBouncycastleOpenpgpPGPSignature_STAND_ALONE;
}

+ (jint)DEFAULT_CERTIFICATION {
  return LibOrgBouncycastleOpenpgpPGPSignature_DEFAULT_CERTIFICATION;
}

+ (jint)NO_CERTIFICATION {
  return LibOrgBouncycastleOpenpgpPGPSignature_NO_CERTIFICATION;
}

+ (jint)CASUAL_CERTIFICATION {
  return LibOrgBouncycastleOpenpgpPGPSignature_CASUAL_CERTIFICATION;
}

+ (jint)POSITIVE_CERTIFICATION {
  return LibOrgBouncycastleOpenpgpPGPSignature_POSITIVE_CERTIFICATION;
}

+ (jint)SUBKEY_BINDING {
  return LibOrgBouncycastleOpenpgpPGPSignature_SUBKEY_BINDING;
}

+ (jint)PRIMARYKEY_BINDING {
  return LibOrgBouncycastleOpenpgpPGPSignature_PRIMARYKEY_BINDING;
}

+ (jint)DIRECT_KEY {
  return LibOrgBouncycastleOpenpgpPGPSignature_DIRECT_KEY;
}

+ (jint)KEY_REVOCATION {
  return LibOrgBouncycastleOpenpgpPGPSignature_KEY_REVOCATION;
}

+ (jint)SUBKEY_REVOCATION {
  return LibOrgBouncycastleOpenpgpPGPSignature_SUBKEY_REVOCATION;
}

+ (jint)CERTIFICATION_REVOCATION {
  return LibOrgBouncycastleOpenpgpPGPSignature_CERTIFICATION_REVOCATION;
}

+ (jint)TIMESTAMP {
  return LibOrgBouncycastleOpenpgpPGPSignature_TIMESTAMP;
}

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)pIn {
  LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgBCPGInputStream_(self, pIn);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleBcpgSignaturePacket:(LibOrgBouncycastleBcpgSignaturePacket *)sigPacket {
  LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_(self, sigPacket);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleBcpgSignaturePacket:(LibOrgBouncycastleBcpgSignaturePacket *)sigPacket
                        withLibOrgBouncycastleBcpgTrustPacket:(LibOrgBouncycastleBcpgTrustPacket *)trustPacket {
  LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_withLibOrgBouncycastleBcpgTrustPacket_(self, sigPacket, trustPacket);
  return self;
}

- (jint)getVersion {
  return [((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getVersion];
}

- (jint)getKeyAlgorithm {
  return [((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getKeyAlgorithm];
}

- (jint)getHashAlgorithm {
  return [((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getHashAlgorithm];
}

- (jboolean)isCertification {
  return LibOrgBouncycastleOpenpgpPGPSignature_isCertificationWithInt_([self getSignatureType]);
}

- (void)init__WithLibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilderProvider:(id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilderProvider>)verifierBuilderProvider
                                           withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey {
  id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilder> verifierBuilder = [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilderProvider>) nil_chk(verifierBuilderProvider)) getWithInt:[((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getKeyAlgorithm] withInt:[((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getHashAlgorithm]];
  verifier_ = [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilder>) nil_chk(verifierBuilder)) buildWithLibOrgBouncycastleOpenpgpPGPPublicKey:pubKey];
  lastb_ = 0;
  sigOut_ = [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifier>) nil_chk(verifier_)) getOutputStream];
}

- (void)updateWithByte:(jbyte)b {
  if (signatureType_ == LibOrgBouncycastleOpenpgpPGPSignature_CANONICAL_TEXT_DOCUMENT) {
    if (b == 0x000d) {
      LibOrgBouncycastleOpenpgpPGPSignature_byteUpdateWithByte_(self, (jbyte) 0x000d);
      LibOrgBouncycastleOpenpgpPGPSignature_byteUpdateWithByte_(self, (jbyte) 0x000a);
    }
    else if (b == 0x000a) {
      if (lastb_ != 0x000d) {
        LibOrgBouncycastleOpenpgpPGPSignature_byteUpdateWithByte_(self, (jbyte) 0x000d);
        LibOrgBouncycastleOpenpgpPGPSignature_byteUpdateWithByte_(self, (jbyte) 0x000a);
      }
    }
    else {
      LibOrgBouncycastleOpenpgpPGPSignature_byteUpdateWithByte_(self, b);
    }
    lastb_ = b;
  }
  else {
    LibOrgBouncycastleOpenpgpPGPSignature_byteUpdateWithByte_(self, b);
  }
}

- (void)updateWithByteArray:(IOSByteArray *)bytes {
  [self updateWithByteArray:bytes withInt:0 withInt:((IOSByteArray *) nil_chk(bytes))->size_];
}

- (void)updateWithByteArray:(IOSByteArray *)bytes
                    withInt:(jint)off
                    withInt:(jint)length {
  if (signatureType_ == LibOrgBouncycastleOpenpgpPGPSignature_CANONICAL_TEXT_DOCUMENT) {
    jint finish = off + length;
    for (jint i = off; i != finish; i++) {
      [self updateWithByte:IOSByteArray_Get(nil_chk(bytes), i)];
    }
  }
  else {
    LibOrgBouncycastleOpenpgpPGPSignature_blockUpdateWithByteArray_withInt_withInt_(self, bytes, off, length);
  }
}

- (void)byteUpdateWithByte:(jbyte)b {
  LibOrgBouncycastleOpenpgpPGPSignature_byteUpdateWithByte_(self, b);
}

- (void)blockUpdateWithByteArray:(IOSByteArray *)block
                         withInt:(jint)off
                         withInt:(jint)len {
  LibOrgBouncycastleOpenpgpPGPSignature_blockUpdateWithByteArray_withInt_withInt_(self, block, off, len);
}

- (jboolean)verify {
  @try {
    [((JavaIoOutputStream *) nil_chk(sigOut_)) writeWithByteArray:[self getSignatureTrailer]];
    [((JavaIoOutputStream *) nil_chk(sigOut_)) close];
  }
  @catch (JavaIoIOException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_([e getMessage], e);
  }
  return [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifier>) nil_chk(verifier_)) verifyWithByteArray:[self getSignature]];
}

- (void)updateWithIdDataWithInt:(jint)header
                  withByteArray:(IOSByteArray *)idBytes {
  LibOrgBouncycastleOpenpgpPGPSignature_updateWithIdDataWithInt_withByteArray_(self, header, idBytes);
}

- (void)updateWithPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key {
  LibOrgBouncycastleOpenpgpPGPSignature_updateWithPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_(self, key);
}

- (jboolean)verifyCertificationWithLibOrgBouncycastleOpenpgpPGPUserAttributeSubpacketVector:(LibOrgBouncycastleOpenpgpPGPUserAttributeSubpacketVector *)userAttributes
                                                  withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key {
  if (verifier_ == nil) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"PGPSignature not initialised - call init().");
  }
  LibOrgBouncycastleOpenpgpPGPSignature_updateWithPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_(self, key);
  @try {
    JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
    IOSObjectArray *packets = [((LibOrgBouncycastleOpenpgpPGPUserAttributeSubpacketVector *) nil_chk(userAttributes)) toSubpacketArray];
    for (jint i = 0; i != ((IOSObjectArray *) nil_chk(packets))->size_; i++) {
      [((LibOrgBouncycastleBcpgUserAttributeSubpacket *) nil_chk(IOSObjectArray_Get(packets, i))) encodeWithJavaIoOutputStream:bOut];
    }
    LibOrgBouncycastleOpenpgpPGPSignature_updateWithIdDataWithInt_withByteArray_(self, (jint) 0xd1, [bOut toByteArray]);
  }
  @catch (JavaIoIOException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(@"cannot encode subpacket array", e);
  }
  LibOrgBouncycastleOpenpgpPGPSignature_addTrailer(self);
  return [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifier>) nil_chk(verifier_)) verifyWithByteArray:[self getSignature]];
}

- (jboolean)verifyCertificationWithNSString:(NSString *)id_
  withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key {
  if (verifier_ == nil) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"PGPSignature not initialised - call init().");
  }
  LibOrgBouncycastleOpenpgpPGPSignature_updateWithPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_(self, key);
  LibOrgBouncycastleOpenpgpPGPSignature_updateWithIdDataWithInt_withByteArray_(self, (jint) 0xb4, LibOrgBouncycastleUtilStrings_toUTF8ByteArrayWithNSString_(id_));
  LibOrgBouncycastleOpenpgpPGPSignature_addTrailer(self);
  return [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifier>) nil_chk(verifier_)) verifyWithByteArray:[self getSignature]];
}

- (jboolean)verifyCertificationWithByteArray:(IOSByteArray *)rawID
   withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key {
  if (verifier_ == nil) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"PGPSignature not initialised - call init().");
  }
  LibOrgBouncycastleOpenpgpPGPSignature_updateWithPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_(self, key);
  LibOrgBouncycastleOpenpgpPGPSignature_updateWithIdDataWithInt_withByteArray_(self, (jint) 0xb4, rawID);
  LibOrgBouncycastleOpenpgpPGPSignature_addTrailer(self);
  return [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifier>) nil_chk(verifier_)) verifyWithByteArray:[self getSignature]];
}

- (jboolean)verifyCertificationWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)masterKey
                               withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey {
  if (verifier_ == nil) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"PGPSignature not initialised - call init().");
  }
  LibOrgBouncycastleOpenpgpPGPSignature_updateWithPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_(self, masterKey);
  LibOrgBouncycastleOpenpgpPGPSignature_updateWithPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_(self, pubKey);
  LibOrgBouncycastleOpenpgpPGPSignature_addTrailer(self);
  return [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifier>) nil_chk(verifier_)) verifyWithByteArray:[self getSignature]];
}

- (void)addTrailer {
  LibOrgBouncycastleOpenpgpPGPSignature_addTrailer(self);
}

- (jboolean)verifyCertificationWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey {
  if (verifier_ == nil) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"PGPSignature not initialised - call init().");
  }
  if ([self getSignatureType] != LibOrgBouncycastleOpenpgpPGPSignature_KEY_REVOCATION && [self getSignatureType] != LibOrgBouncycastleOpenpgpPGPSignature_SUBKEY_REVOCATION && [self getSignatureType] != LibOrgBouncycastleOpenpgpPGPSignature_DIRECT_KEY) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"signature is not a key signature");
  }
  LibOrgBouncycastleOpenpgpPGPSignature_updateWithPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_(self, pubKey);
  LibOrgBouncycastleOpenpgpPGPSignature_addTrailer(self);
  return [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifier>) nil_chk(verifier_)) verifyWithByteArray:[self getSignature]];
}

- (jint)getSignatureType {
  return [((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getSignatureType];
}

- (jlong)getKeyID {
  return [((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getKeyID];
}

- (JavaUtilDate *)getCreationTime {
  return new_JavaUtilDate_initWithLong_([((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getCreationTime]);
}

- (IOSByteArray *)getSignatureTrailer {
  return [((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getSignatureTrailer];
}

- (jboolean)hasSubpackets {
  return [((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getHashedSubPackets] != nil || [((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getUnhashedSubPackets] != nil;
}

- (LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *)getHashedSubPackets {
  return LibOrgBouncycastleOpenpgpPGPSignature_createSubpacketVectorWithLibOrgBouncycastleBcpgSignatureSubpacketArray_(self, [((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getHashedSubPackets]);
}

- (LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *)getUnhashedSubPackets {
  return LibOrgBouncycastleOpenpgpPGPSignature_createSubpacketVectorWithLibOrgBouncycastleBcpgSignatureSubpacketArray_(self, [((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getUnhashedSubPackets]);
}

- (LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *)createSubpacketVectorWithLibOrgBouncycastleBcpgSignatureSubpacketArray:(IOSObjectArray *)pcks {
  return LibOrgBouncycastleOpenpgpPGPSignature_createSubpacketVectorWithLibOrgBouncycastleBcpgSignatureSubpacketArray_(self, pcks);
}

- (IOSByteArray *)getSignature {
  IOSObjectArray *sigValues = [((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getSignature];
  IOSByteArray *signature;
  if (sigValues != nil) {
    if (sigValues->size_ == 1) {
      signature = LibOrgBouncycastleUtilBigIntegers_asUnsignedByteArrayWithJavaMathBigInteger_([((LibOrgBouncycastleBcpgMPInteger *) nil_chk(IOSObjectArray_Get(sigValues, 0))) getValue]);
    }
    else {
      @try {
        LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
        [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_([((LibOrgBouncycastleBcpgMPInteger *) nil_chk(IOSObjectArray_Get(sigValues, 0))) getValue])];
        [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_([((LibOrgBouncycastleBcpgMPInteger *) nil_chk(IOSObjectArray_Get(sigValues, 1))) getValue])];
        signature = [new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v) getEncoded];
      }
      @catch (JavaIoIOException *e) {
        @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(@"exception encoding DSA sig.", e);
      }
    }
  }
  else {
    signature = [((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(sigPck_)) getSignatureBytes];
  }
  return signature;
}

- (IOSByteArray *)getEncoded {
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  [self encodeWithJavaIoOutputStream:bOut];
  return [bOut toByteArray];
}

- (IOSByteArray *)getEncodedWithBoolean:(jboolean)forTransfer {
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  [self encodeWithJavaIoOutputStream:bOut withBoolean:forTransfer];
  return [bOut toByteArray];
}

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)outStream {
  [self encodeWithJavaIoOutputStream:outStream withBoolean:false];
}

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)outStream
                         withBoolean:(jboolean)forTransfer {
  LibOrgBouncycastleBcpgBCPGOutputStream *out;
  if ([outStream isKindOfClass:[LibOrgBouncycastleBcpgBCPGOutputStream class]]) {
    out = (LibOrgBouncycastleBcpgBCPGOutputStream *) outStream;
  }
  else {
    out = new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_(outStream);
  }
  [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(out)) writePacketWithLibOrgBouncycastleBcpgContainedPacket:sigPck_];
  if (!forTransfer && trustPck_ != nil) {
    [out writePacketWithLibOrgBouncycastleBcpgContainedPacket:trustPck_];
  }
}

- (IOSByteArray *)getEncodedPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey {
  return LibOrgBouncycastleOpenpgpPGPSignature_getEncodedPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_(self, pubKey);
}

+ (jboolean)isCertificationWithInt:(jint)signatureType {
  return LibOrgBouncycastleOpenpgpPGPSignature_isCertificationWithInt_(signatureType);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 2, 3, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 4, 3, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 7, 9, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 7, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 11, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 12, 10, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, 3, -1, -1, -1 },
    { NULL, "V", 0x2, 13, 14, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 15, 16, 3, -1, -1, -1 },
    { NULL, "Z", 0x1, 17, 18, 3, -1, -1, -1 },
    { NULL, "Z", 0x1, 17, 19, 3, -1, -1, -1 },
    { NULL, "Z", 0x1, 17, 20, 3, -1, -1, -1 },
    { NULL, "Z", 0x1, 17, 21, 3, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 17, 16, 3, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilDate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector;", 0x2, 22, 23, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 3, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 24, -1, -1, -1 },
    { NULL, "[B", 0x1, 25, 26, 24, -1, -1, -1 },
    { NULL, "V", 0x1, 27, 28, 24, -1, -1, -1 },
    { NULL, "V", 0x1, 27, 29, 24, -1, -1, -1 },
    { NULL, "[B", 0x2, 30, 16, 3, -1, -1, -1 },
    { NULL, "Z", 0x9, 31, 32, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleBcpgSignaturePacket:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleBcpgSignaturePacket:withLibOrgBouncycastleBcpgTrustPacket:);
  methods[3].selector = @selector(getVersion);
  methods[4].selector = @selector(getKeyAlgorithm);
  methods[5].selector = @selector(getHashAlgorithm);
  methods[6].selector = @selector(isCertification);
  methods[7].selector = @selector(init__WithLibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilderProvider:withLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[8].selector = @selector(updateWithByte:);
  methods[9].selector = @selector(updateWithByteArray:);
  methods[10].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[11].selector = @selector(byteUpdateWithByte:);
  methods[12].selector = @selector(blockUpdateWithByteArray:withInt:withInt:);
  methods[13].selector = @selector(verify);
  methods[14].selector = @selector(updateWithIdDataWithInt:withByteArray:);
  methods[15].selector = @selector(updateWithPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[16].selector = @selector(verifyCertificationWithLibOrgBouncycastleOpenpgpPGPUserAttributeSubpacketVector:withLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[17].selector = @selector(verifyCertificationWithNSString:withLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[18].selector = @selector(verifyCertificationWithByteArray:withLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[19].selector = @selector(verifyCertificationWithLibOrgBouncycastleOpenpgpPGPPublicKey:withLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[20].selector = @selector(addTrailer);
  methods[21].selector = @selector(verifyCertificationWithLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[22].selector = @selector(getSignatureType);
  methods[23].selector = @selector(getKeyID);
  methods[24].selector = @selector(getCreationTime);
  methods[25].selector = @selector(getSignatureTrailer);
  methods[26].selector = @selector(hasSubpackets);
  methods[27].selector = @selector(getHashedSubPackets);
  methods[28].selector = @selector(getUnhashedSubPackets);
  methods[29].selector = @selector(createSubpacketVectorWithLibOrgBouncycastleBcpgSignatureSubpacketArray:);
  methods[30].selector = @selector(getSignature);
  methods[31].selector = @selector(getEncoded);
  methods[32].selector = @selector(getEncodedWithBoolean:);
  methods[33].selector = @selector(encodeWithJavaIoOutputStream:);
  methods[34].selector = @selector(encodeWithJavaIoOutputStream:withBoolean:);
  methods[35].selector = @selector(getEncodedPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[36].selector = @selector(isCertificationWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "BINARY_DOCUMENT", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_BINARY_DOCUMENT, 0x19, -1, -1, -1, -1 },
    { "CANONICAL_TEXT_DOCUMENT", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_CANONICAL_TEXT_DOCUMENT, 0x19, -1, -1, -1, -1 },
    { "STAND_ALONE", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_STAND_ALONE, 0x19, -1, -1, -1, -1 },
    { "DEFAULT_CERTIFICATION", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_DEFAULT_CERTIFICATION, 0x19, -1, -1, -1, -1 },
    { "NO_CERTIFICATION", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_NO_CERTIFICATION, 0x19, -1, -1, -1, -1 },
    { "CASUAL_CERTIFICATION", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_CASUAL_CERTIFICATION, 0x19, -1, -1, -1, -1 },
    { "POSITIVE_CERTIFICATION", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_POSITIVE_CERTIFICATION, 0x19, -1, -1, -1, -1 },
    { "SUBKEY_BINDING", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_SUBKEY_BINDING, 0x19, -1, -1, -1, -1 },
    { "PRIMARYKEY_BINDING", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_PRIMARYKEY_BINDING, 0x19, -1, -1, -1, -1 },
    { "DIRECT_KEY", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_DIRECT_KEY, 0x19, -1, -1, -1, -1 },
    { "KEY_REVOCATION", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_KEY_REVOCATION, 0x19, -1, -1, -1, -1 },
    { "SUBKEY_REVOCATION", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_SUBKEY_REVOCATION, 0x19, -1, -1, -1, -1 },
    { "CERTIFICATION_REVOCATION", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_CERTIFICATION_REVOCATION, 0x19, -1, -1, -1, -1 },
    { "TIMESTAMP", "I", .constantValue.asInt = LibOrgBouncycastleOpenpgpPGPSignature_TIMESTAMP, 0x19, -1, -1, -1, -1 },
    { "sigPck_", "LLibOrgBouncycastleBcpgSignaturePacket;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "signatureType_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "trustPck_", "LLibOrgBouncycastleBcpgTrustPacket;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "verifier_", "LLibOrgBouncycastleOpenpgpOperatorPGPContentVerifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "lastb_", "B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sigOut_", "LJavaIoOutputStream;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleBcpgBCPGInputStream;", "LJavaIoIOException;LLibOrgBouncycastleOpenpgpPGPException;", "LLibOrgBouncycastleBcpgSignaturePacket;", "LLibOrgBouncycastleOpenpgpPGPException;", "LLibOrgBouncycastleBcpgSignaturePacket;LLibOrgBouncycastleBcpgTrustPacket;", "init", "LLibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilderProvider;LLibOrgBouncycastleOpenpgpPGPPublicKey;", "update", "B", "[B", "[BII", "byteUpdate", "blockUpdate", "updateWithIdData", "I[B", "updateWithPublicKey", "LLibOrgBouncycastleOpenpgpPGPPublicKey;", "verifyCertification", "LLibOrgBouncycastleOpenpgpPGPUserAttributeSubpacketVector;LLibOrgBouncycastleOpenpgpPGPPublicKey;", "LNSString;LLibOrgBouncycastleOpenpgpPGPPublicKey;", "[BLLibOrgBouncycastleOpenpgpPGPPublicKey;", "LLibOrgBouncycastleOpenpgpPGPPublicKey;LLibOrgBouncycastleOpenpgpPGPPublicKey;", "createSubpacketVector", "[LLibOrgBouncycastleBcpgSignatureSubpacket;", "LJavaIoIOException;", "getEncoded", "Z", "encode", "LJavaIoOutputStream;", "LJavaIoOutputStream;Z", "getEncodedPublicKey", "isCertification", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpPGPSignature = { "PGPSignature", "lib.org.bouncycastle.openpgp", ptrTable, methods, fields, 7, 0x1, 37, 20, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpPGPSignature;
}

@end

void LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleOpenpgpPGPSignature *self, LibOrgBouncycastleBcpgBCPGInputStream *pIn) {
  LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_(self, (LibOrgBouncycastleBcpgSignaturePacket *) cast_chk([((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(pIn)) readPacket], [LibOrgBouncycastleBcpgSignaturePacket class]));
}

LibOrgBouncycastleOpenpgpPGPSignature *new_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *pIn) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPSignature, initWithLibOrgBouncycastleBcpgBCPGInputStream_, pIn)
}

LibOrgBouncycastleOpenpgpPGPSignature *create_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *pIn) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPSignature, initWithLibOrgBouncycastleBcpgBCPGInputStream_, pIn)
}

void LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_(LibOrgBouncycastleOpenpgpPGPSignature *self, LibOrgBouncycastleBcpgSignaturePacket *sigPacket) {
  NSObject_init(self);
  self->sigPck_ = sigPacket;
  self->signatureType_ = [((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(self->sigPck_)) getSignatureType];
  self->trustPck_ = nil;
}

LibOrgBouncycastleOpenpgpPGPSignature *new_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_(LibOrgBouncycastleBcpgSignaturePacket *sigPacket) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPSignature, initWithLibOrgBouncycastleBcpgSignaturePacket_, sigPacket)
}

LibOrgBouncycastleOpenpgpPGPSignature *create_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_(LibOrgBouncycastleBcpgSignaturePacket *sigPacket) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPSignature, initWithLibOrgBouncycastleBcpgSignaturePacket_, sigPacket)
}

void LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_withLibOrgBouncycastleBcpgTrustPacket_(LibOrgBouncycastleOpenpgpPGPSignature *self, LibOrgBouncycastleBcpgSignaturePacket *sigPacket, LibOrgBouncycastleBcpgTrustPacket *trustPacket) {
  LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_(self, sigPacket);
  self->trustPck_ = trustPacket;
}

LibOrgBouncycastleOpenpgpPGPSignature *new_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_withLibOrgBouncycastleBcpgTrustPacket_(LibOrgBouncycastleBcpgSignaturePacket *sigPacket, LibOrgBouncycastleBcpgTrustPacket *trustPacket) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPSignature, initWithLibOrgBouncycastleBcpgSignaturePacket_withLibOrgBouncycastleBcpgTrustPacket_, sigPacket, trustPacket)
}

LibOrgBouncycastleOpenpgpPGPSignature *create_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_withLibOrgBouncycastleBcpgTrustPacket_(LibOrgBouncycastleBcpgSignaturePacket *sigPacket, LibOrgBouncycastleBcpgTrustPacket *trustPacket) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPSignature, initWithLibOrgBouncycastleBcpgSignaturePacket_withLibOrgBouncycastleBcpgTrustPacket_, sigPacket, trustPacket)
}

void LibOrgBouncycastleOpenpgpPGPSignature_byteUpdateWithByte_(LibOrgBouncycastleOpenpgpPGPSignature *self, jbyte b) {
  @try {
    [((JavaIoOutputStream *) nil_chk(self->sigOut_)) writeWithInt:b];
  }
  @catch (JavaIoIOException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPRuntimeOperationException_initWithNSString_withJavaLangThrowable_([e getMessage], e);
  }
}

void LibOrgBouncycastleOpenpgpPGPSignature_blockUpdateWithByteArray_withInt_withInt_(LibOrgBouncycastleOpenpgpPGPSignature *self, IOSByteArray *block, jint off, jint len) {
  @try {
    [((JavaIoOutputStream *) nil_chk(self->sigOut_)) writeWithByteArray:block withInt:off withInt:len];
  }
  @catch (JavaIoIOException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPRuntimeOperationException_initWithNSString_withJavaLangThrowable_([e getMessage], e);
  }
}

void LibOrgBouncycastleOpenpgpPGPSignature_updateWithIdDataWithInt_withByteArray_(LibOrgBouncycastleOpenpgpPGPSignature *self, jint header, IOSByteArray *idBytes) {
  [self updateWithByte:(jbyte) header];
  [self updateWithByte:(jbyte) (JreRShift32(((IOSByteArray *) nil_chk(idBytes))->size_, 24))];
  [self updateWithByte:(jbyte) (JreRShift32(idBytes->size_, 16))];
  [self updateWithByte:(jbyte) (JreRShift32(idBytes->size_, 8))];
  [self updateWithByte:(jbyte) (idBytes->size_)];
  [self updateWithByteArray:idBytes];
}

void LibOrgBouncycastleOpenpgpPGPSignature_updateWithPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPSignature *self, LibOrgBouncycastleOpenpgpPGPPublicKey *key) {
  IOSByteArray *keyBytes = LibOrgBouncycastleOpenpgpPGPSignature_getEncodedPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_(self, key);
  [self updateWithByte:(jbyte) (jint) 0x99];
  [self updateWithByte:(jbyte) (JreRShift32(((IOSByteArray *) nil_chk(keyBytes))->size_, 8))];
  [self updateWithByte:(jbyte) (keyBytes->size_)];
  [self updateWithByteArray:keyBytes];
}

void LibOrgBouncycastleOpenpgpPGPSignature_addTrailer(LibOrgBouncycastleOpenpgpPGPSignature *self) {
  @try {
    [((JavaIoOutputStream *) nil_chk(self->sigOut_)) writeWithByteArray:[((LibOrgBouncycastleBcpgSignaturePacket *) nil_chk(self->sigPck_)) getSignatureTrailer]];
    [((JavaIoOutputStream *) nil_chk(self->sigOut_)) close];
  }
  @catch (JavaIoIOException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPRuntimeOperationException_initWithNSString_withJavaLangThrowable_([e getMessage], e);
  }
}

LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *LibOrgBouncycastleOpenpgpPGPSignature_createSubpacketVectorWithLibOrgBouncycastleBcpgSignatureSubpacketArray_(LibOrgBouncycastleOpenpgpPGPSignature *self, IOSObjectArray *pcks) {
  if (pcks != nil) {
    return new_LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_initWithLibOrgBouncycastleBcpgSignatureSubpacketArray_(pcks);
  }
  return nil;
}

IOSByteArray *LibOrgBouncycastleOpenpgpPGPSignature_getEncodedPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPSignature *self, LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey) {
  IOSByteArray *keyBytes;
  @try {
    keyBytes = [((LibOrgBouncycastleBcpgPublicKeyPacket *) nil_chk(((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(pubKey))->publicPk_)) getEncodedContents];
  }
  @catch (JavaIoIOException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(@"exception preparing key.", e);
  }
  return keyBytes;
}

jboolean LibOrgBouncycastleOpenpgpPGPSignature_isCertificationWithInt_(jint signatureType) {
  LibOrgBouncycastleOpenpgpPGPSignature_initialize();
  return LibOrgBouncycastleOpenpgpPGPSignature_DEFAULT_CERTIFICATION == signatureType || LibOrgBouncycastleOpenpgpPGPSignature_NO_CERTIFICATION == signatureType || LibOrgBouncycastleOpenpgpPGPSignature_CASUAL_CERTIFICATION == signatureType || LibOrgBouncycastleOpenpgpPGPSignature_POSITIVE_CERTIFICATION == signatureType;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpPGPSignature)
