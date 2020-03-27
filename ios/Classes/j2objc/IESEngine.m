//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/IESEngine.java
//

#include "Arrays.h"
#include "AsymmetricCipherKeyPair.h"
#include "AsymmetricKeyParameter.h"
#include "BasicAgreement.h"
#include "BigIntegers.h"
#include "BufferedBlockCipher.h"
#include "CipherParameters.h"
#include "DerivationFunction.h"
#include "EphemeralKeyPair.h"
#include "EphemeralKeyPairGenerator.h"
#include "IESEngine.h"
#include "IESParameters.h"
#include "IESWithCipherParameters.h"
#include "IOSPrimitiveArray.h"
#include "InvalidCipherTextException.h"
#include "J2ObjC_source.h"
#include "KDFParameters.h"
#include "KeyParameter.h"
#include "KeyParser.h"
#include "Mac.h"
#include "Pack.h"
#include "ParametersWithIV.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoEnginesIESEngine () {
 @public
  LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator *keyPairGenerator_;
  id<LibOrgBouncycastleCryptoKeyParser> keyParser_;
  IOSByteArray *IV_;
}

- (void)extractParamsWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params;

- (IOSByteArray *)encryptBlockWithByteArray:(IOSByteArray *)inArg
                                    withInt:(jint)inOff
                                    withInt:(jint)inLen;

- (IOSByteArray *)decryptBlockWithByteArray:(IOSByteArray *)in_enc
                                    withInt:(jint)inOff
                                    withInt:(jint)inLen;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesIESEngine, keyPairGenerator_, LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesIESEngine, keyParser_, id<LibOrgBouncycastleCryptoKeyParser>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesIESEngine, IV_, IOSByteArray *)

__attribute__((unused)) static void LibOrgBouncycastleCryptoEnginesIESEngine_extractParamsWithLibOrgBouncycastleCryptoCipherParameters_(LibOrgBouncycastleCryptoEnginesIESEngine *self, id<LibOrgBouncycastleCryptoCipherParameters> params);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoEnginesIESEngine_encryptBlockWithByteArray_withInt_withInt_(LibOrgBouncycastleCryptoEnginesIESEngine *self, IOSByteArray *inArg, jint inOff, jint inLen);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoEnginesIESEngine_decryptBlockWithByteArray_withInt_withInt_(LibOrgBouncycastleCryptoEnginesIESEngine *self, IOSByteArray *in_enc, jint inOff, jint inLen);

@implementation LibOrgBouncycastleCryptoEnginesIESEngine

- (instancetype)initWithLibOrgBouncycastleCryptoBasicAgreement:(id<LibOrgBouncycastleCryptoBasicAgreement>)agree
                withLibOrgBouncycastleCryptoDerivationFunction:(id<LibOrgBouncycastleCryptoDerivationFunction>)kdf
                               withLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)mac {
  LibOrgBouncycastleCryptoEnginesIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_(self, agree, kdf, mac);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoBasicAgreement:(id<LibOrgBouncycastleCryptoBasicAgreement>)agree
                withLibOrgBouncycastleCryptoDerivationFunction:(id<LibOrgBouncycastleCryptoDerivationFunction>)kdf
                               withLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)mac
               withLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)cipher {
  LibOrgBouncycastleCryptoEnginesIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_withLibOrgBouncycastleCryptoBufferedBlockCipher_(self, agree, kdf, mac, cipher);
  return self;
}

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)privParam
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)pubParam
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  self->forEncryption_ = forEncryption;
  self->privParam_ = privParam;
  self->pubParam_ = pubParam;
  self->V_ = [IOSByteArray newArrayWithLength:0];
  LibOrgBouncycastleCryptoEnginesIESEngine_extractParamsWithLibOrgBouncycastleCryptoCipherParameters_(self, params);
}

- (void)init__WithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicKey
                          withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params
       withLibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator:(LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator *)ephemeralKeyPairGenerator {
  self->forEncryption_ = true;
  self->pubParam_ = publicKey;
  self->keyPairGenerator_ = ephemeralKeyPairGenerator;
  LibOrgBouncycastleCryptoEnginesIESEngine_extractParamsWithLibOrgBouncycastleCryptoCipherParameters_(self, params);
}

- (void)init__WithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateKey
                          withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params
                                 withLibOrgBouncycastleCryptoKeyParser:(id<LibOrgBouncycastleCryptoKeyParser>)publicKeyParser {
  self->forEncryption_ = false;
  self->privParam_ = privateKey;
  self->keyParser_ = publicKeyParser;
  LibOrgBouncycastleCryptoEnginesIESEngine_extractParamsWithLibOrgBouncycastleCryptoCipherParameters_(self, params);
}

- (void)extractParamsWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  LibOrgBouncycastleCryptoEnginesIESEngine_extractParamsWithLibOrgBouncycastleCryptoCipherParameters_(self, params);
}

- (LibOrgBouncycastleCryptoBufferedBlockCipher *)getCipher {
  return cipher_;
}

- (id<LibOrgBouncycastleCryptoMac>)getMac {
  return mac_;
}

- (IOSByteArray *)encryptBlockWithByteArray:(IOSByteArray *)inArg
                                    withInt:(jint)inOff
                                    withInt:(jint)inLen {
  return LibOrgBouncycastleCryptoEnginesIESEngine_encryptBlockWithByteArray_withInt_withInt_(self, inArg, inOff, inLen);
}

- (IOSByteArray *)decryptBlockWithByteArray:(IOSByteArray *)in_enc
                                    withInt:(jint)inOff
                                    withInt:(jint)inLen {
  return LibOrgBouncycastleCryptoEnginesIESEngine_decryptBlockWithByteArray_withInt_withInt_(self, in_enc, inOff, inLen);
}

- (IOSByteArray *)processBlockWithByteArray:(IOSByteArray *)inArg
                                    withInt:(jint)inOff
                                    withInt:(jint)inLen {
  if (forEncryption_) {
    if (keyPairGenerator_ != nil) {
      LibOrgBouncycastleCryptoEphemeralKeyPair *ephKeyPair = [keyPairGenerator_ generate];
      self->privParam_ = [((LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *) nil_chk([((LibOrgBouncycastleCryptoEphemeralKeyPair *) nil_chk(ephKeyPair)) getKeyPair])) getPrivate];
      self->V_ = [ephKeyPair getEncodedPublicKey];
    }
  }
  else {
    if (keyParser_ != nil) {
      JavaIoByteArrayInputStream *bIn = new_JavaIoByteArrayInputStream_initWithByteArray_withInt_withInt_(inArg, inOff, inLen);
      @try {
        self->pubParam_ = [((id<LibOrgBouncycastleCryptoKeyParser>) nil_chk(keyParser_)) readKeyWithJavaIoInputStream:bIn];
      }
      @catch (JavaIoIOException *e) {
        @throw new_LibOrgBouncycastleCryptoInvalidCipherTextException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"unable to recover ephemeral public key: ", [e getMessage]), e);
      }
      @catch (JavaLangIllegalArgumentException *e) {
        @throw new_LibOrgBouncycastleCryptoInvalidCipherTextException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"unable to recover ephemeral public key: ", [e getMessage]), e);
      }
      jint encLength = (inLen - [bIn available]);
      self->V_ = LibOrgBouncycastleUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(inArg, inOff, inOff + encLength);
    }
  }
  [((id<LibOrgBouncycastleCryptoBasicAgreement>) nil_chk(agree_)) init__WithLibOrgBouncycastleCryptoCipherParameters:privParam_];
  JavaMathBigInteger *z = [((id<LibOrgBouncycastleCryptoBasicAgreement>) nil_chk(agree_)) calculateAgreementWithLibOrgBouncycastleCryptoCipherParameters:pubParam_];
  IOSByteArray *Z = LibOrgBouncycastleUtilBigIntegers_asUnsignedByteArrayWithInt_withJavaMathBigInteger_([((id<LibOrgBouncycastleCryptoBasicAgreement>) nil_chk(agree_)) getFieldSize], z);
  if (((IOSByteArray *) nil_chk(V_))->size_ != 0) {
    IOSByteArray *VZ = LibOrgBouncycastleUtilArrays_concatenateWithByteArray_withByteArray_(V_, Z);
    LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(Z, (jbyte) 0);
    Z = VZ;
  }
  @try {
    LibOrgBouncycastleCryptoParamsKDFParameters *kdfParam = new_LibOrgBouncycastleCryptoParamsKDFParameters_initWithByteArray_withByteArray_(Z, [((LibOrgBouncycastleCryptoParamsIESParameters *) nil_chk(param_)) getDerivationV]);
    [((id<LibOrgBouncycastleCryptoDerivationFunction>) nil_chk(kdf_)) init__WithLibOrgBouncycastleCryptoDerivationParameters:kdfParam];
    return forEncryption_ ? LibOrgBouncycastleCryptoEnginesIESEngine_encryptBlockWithByteArray_withInt_withInt_(self, inArg, inOff, inLen) : LibOrgBouncycastleCryptoEnginesIESEngine_decryptBlockWithByteArray_withInt_withInt_(self, inArg, inOff, inLen);
  }
  @finally {
    LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(Z, (jbyte) 0);
  }
}

- (IOSByteArray *)getLengthTagWithByteArray:(IOSByteArray *)p2 {
  IOSByteArray *L2 = [IOSByteArray newArrayWithLength:8];
  if (p2 != nil) {
    LibOrgBouncycastleUtilPack_longToBigEndianWithLong_withByteArray_withInt_(p2->size_ * 8LL, L2, 0);
  }
  return L2;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoBufferedBlockCipher;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoMac;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 8, 9, 10, -1, -1, -1 },
    { NULL, "[B", 0x2, 11, 9, 10, -1, -1, -1 },
    { NULL, "[B", 0x1, 12, 9, 10, -1, -1, -1 },
    { NULL, "[B", 0x4, 13, 14, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoBasicAgreement:withLibOrgBouncycastleCryptoDerivationFunction:withLibOrgBouncycastleCryptoMac:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoBasicAgreement:withLibOrgBouncycastleCryptoDerivationFunction:withLibOrgBouncycastleCryptoMac:withLibOrgBouncycastleCryptoBufferedBlockCipher:);
  methods[2].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:withLibOrgBouncycastleCryptoCipherParameters:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[3].selector = @selector(init__WithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:withLibOrgBouncycastleCryptoCipherParameters:withLibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator:);
  methods[4].selector = @selector(init__WithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:withLibOrgBouncycastleCryptoCipherParameters:withLibOrgBouncycastleCryptoKeyParser:);
  methods[5].selector = @selector(extractParamsWithLibOrgBouncycastleCryptoCipherParameters:);
  methods[6].selector = @selector(getCipher);
  methods[7].selector = @selector(getMac);
  methods[8].selector = @selector(encryptBlockWithByteArray:withInt:withInt:);
  methods[9].selector = @selector(decryptBlockWithByteArray:withInt:withInt:);
  methods[10].selector = @selector(processBlockWithByteArray:withInt:withInt:);
  methods[11].selector = @selector(getLengthTagWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "agree_", "LLibOrgBouncycastleCryptoBasicAgreement;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "kdf_", "LLibOrgBouncycastleCryptoDerivationFunction;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "mac_", "LLibOrgBouncycastleCryptoMac;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "cipher_", "LLibOrgBouncycastleCryptoBufferedBlockCipher;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "macBuf_", "[B", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "forEncryption_", "Z", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "privParam_", "LLibOrgBouncycastleCryptoCipherParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "pubParam_", "LLibOrgBouncycastleCryptoCipherParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "param_", "LLibOrgBouncycastleCryptoParamsIESParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "V_", "[B", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "keyPairGenerator_", "LLibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyParser_", "LLibOrgBouncycastleCryptoKeyParser;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "IV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoBasicAgreement;LLibOrgBouncycastleCryptoDerivationFunction;LLibOrgBouncycastleCryptoMac;", "LLibOrgBouncycastleCryptoBasicAgreement;LLibOrgBouncycastleCryptoDerivationFunction;LLibOrgBouncycastleCryptoMac;LLibOrgBouncycastleCryptoBufferedBlockCipher;", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;LLibOrgBouncycastleCryptoCipherParameters;LLibOrgBouncycastleCryptoCipherParameters;", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;LLibOrgBouncycastleCryptoCipherParameters;LLibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator;", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;LLibOrgBouncycastleCryptoCipherParameters;LLibOrgBouncycastleCryptoKeyParser;", "extractParams", "LLibOrgBouncycastleCryptoCipherParameters;", "encryptBlock", "[BII", "LLibOrgBouncycastleCryptoInvalidCipherTextException;", "decryptBlock", "processBlock", "getLengthTag", "[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesIESEngine = { "IESEngine", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 12, 13, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesIESEngine;
}

@end

void LibOrgBouncycastleCryptoEnginesIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_(LibOrgBouncycastleCryptoEnginesIESEngine *self, id<LibOrgBouncycastleCryptoBasicAgreement> agree, id<LibOrgBouncycastleCryptoDerivationFunction> kdf, id<LibOrgBouncycastleCryptoMac> mac) {
  NSObject_init(self);
  self->agree_ = agree;
  self->kdf_ = kdf;
  self->mac_ = mac;
  self->macBuf_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoMac>) nil_chk(mac)) getMacSize]];
  self->cipher_ = nil;
}

LibOrgBouncycastleCryptoEnginesIESEngine *new_LibOrgBouncycastleCryptoEnginesIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_(id<LibOrgBouncycastleCryptoBasicAgreement> agree, id<LibOrgBouncycastleCryptoDerivationFunction> kdf, id<LibOrgBouncycastleCryptoMac> mac) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesIESEngine, initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_, agree, kdf, mac)
}

LibOrgBouncycastleCryptoEnginesIESEngine *create_LibOrgBouncycastleCryptoEnginesIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_(id<LibOrgBouncycastleCryptoBasicAgreement> agree, id<LibOrgBouncycastleCryptoDerivationFunction> kdf, id<LibOrgBouncycastleCryptoMac> mac) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesIESEngine, initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_, agree, kdf, mac)
}

void LibOrgBouncycastleCryptoEnginesIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_withLibOrgBouncycastleCryptoBufferedBlockCipher_(LibOrgBouncycastleCryptoEnginesIESEngine *self, id<LibOrgBouncycastleCryptoBasicAgreement> agree, id<LibOrgBouncycastleCryptoDerivationFunction> kdf, id<LibOrgBouncycastleCryptoMac> mac, LibOrgBouncycastleCryptoBufferedBlockCipher *cipher) {
  NSObject_init(self);
  self->agree_ = agree;
  self->kdf_ = kdf;
  self->mac_ = mac;
  self->macBuf_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoMac>) nil_chk(mac)) getMacSize]];
  self->cipher_ = cipher;
}

LibOrgBouncycastleCryptoEnginesIESEngine *new_LibOrgBouncycastleCryptoEnginesIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_withLibOrgBouncycastleCryptoBufferedBlockCipher_(id<LibOrgBouncycastleCryptoBasicAgreement> agree, id<LibOrgBouncycastleCryptoDerivationFunction> kdf, id<LibOrgBouncycastleCryptoMac> mac, LibOrgBouncycastleCryptoBufferedBlockCipher *cipher) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesIESEngine, initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_withLibOrgBouncycastleCryptoBufferedBlockCipher_, agree, kdf, mac, cipher)
}

LibOrgBouncycastleCryptoEnginesIESEngine *create_LibOrgBouncycastleCryptoEnginesIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_withLibOrgBouncycastleCryptoBufferedBlockCipher_(id<LibOrgBouncycastleCryptoBasicAgreement> agree, id<LibOrgBouncycastleCryptoDerivationFunction> kdf, id<LibOrgBouncycastleCryptoMac> mac, LibOrgBouncycastleCryptoBufferedBlockCipher *cipher) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesIESEngine, initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_withLibOrgBouncycastleCryptoBufferedBlockCipher_, agree, kdf, mac, cipher)
}

void LibOrgBouncycastleCryptoEnginesIESEngine_extractParamsWithLibOrgBouncycastleCryptoCipherParameters_(LibOrgBouncycastleCryptoEnginesIESEngine *self, id<LibOrgBouncycastleCryptoCipherParameters> params) {
  if ([params isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithIV class]]) {
    self->IV_ = [((LibOrgBouncycastleCryptoParamsParametersWithIV *) nil_chk(((LibOrgBouncycastleCryptoParamsParametersWithIV *) params))) getIV];
    self->param_ = (LibOrgBouncycastleCryptoParamsIESParameters *) cast_chk([((LibOrgBouncycastleCryptoParamsParametersWithIV *) nil_chk(((LibOrgBouncycastleCryptoParamsParametersWithIV *) params))) getParameters], [LibOrgBouncycastleCryptoParamsIESParameters class]);
  }
  else {
    self->IV_ = nil;
    self->param_ = (LibOrgBouncycastleCryptoParamsIESParameters *) cast_chk(params, [LibOrgBouncycastleCryptoParamsIESParameters class]);
  }
}

IOSByteArray *LibOrgBouncycastleCryptoEnginesIESEngine_encryptBlockWithByteArray_withInt_withInt_(LibOrgBouncycastleCryptoEnginesIESEngine *self, IOSByteArray *inArg, jint inOff, jint inLen) {
  IOSByteArray *C = nil;
  IOSByteArray *K = nil;
  IOSByteArray *K1 = nil;
  IOSByteArray *K2 = nil;
  jint len;
  if (self->cipher_ == nil) {
    K1 = [IOSByteArray newArrayWithLength:inLen];
    K2 = [IOSByteArray newArrayWithLength:[((LibOrgBouncycastleCryptoParamsIESParameters *) nil_chk(self->param_)) getMacKeySize] / 8];
    K = [IOSByteArray newArrayWithLength:K1->size_ + K2->size_];
    [((id<LibOrgBouncycastleCryptoDerivationFunction>) nil_chk(self->kdf_)) generateBytesWithByteArray:K withInt:0 withInt:K->size_];
    if (((IOSByteArray *) nil_chk(self->V_))->size_ != 0) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, 0, K2, 0, K2->size_);
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, K2->size_, K1, 0, K1->size_);
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, 0, K1, 0, K1->size_);
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, inLen, K2, 0, K2->size_);
    }
    C = [IOSByteArray newArrayWithLength:inLen];
    for (jint i = 0; i != inLen; i++) {
      *IOSByteArray_GetRef(C, i) = (jbyte) (IOSByteArray_Get(nil_chk(inArg), inOff + i) ^ IOSByteArray_Get(K1, i));
    }
    len = inLen;
  }
  else {
    K1 = [IOSByteArray newArrayWithLength:[((LibOrgBouncycastleCryptoParamsIESWithCipherParameters *) nil_chk(((LibOrgBouncycastleCryptoParamsIESWithCipherParameters *) cast_chk(self->param_, [LibOrgBouncycastleCryptoParamsIESWithCipherParameters class])))) getCipherKeySize] / 8];
    K2 = [IOSByteArray newArrayWithLength:[((LibOrgBouncycastleCryptoParamsIESParameters *) nil_chk(self->param_)) getMacKeySize] / 8];
    K = [IOSByteArray newArrayWithLength:K1->size_ + K2->size_];
    [((id<LibOrgBouncycastleCryptoDerivationFunction>) nil_chk(self->kdf_)) generateBytesWithByteArray:K withInt:0 withInt:K->size_];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, 0, K1, 0, K1->size_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, K1->size_, K2, 0, K2->size_);
    if (self->IV_ != nil) {
      [((LibOrgBouncycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_(K1), self->IV_)];
    }
    else {
      [((LibOrgBouncycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_(K1)];
    }
    C = [IOSByteArray newArrayWithLength:[((LibOrgBouncycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) getOutputSizeWithInt:inLen]];
    len = [((LibOrgBouncycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) processBytesWithByteArray:inArg withInt:inOff withInt:inLen withByteArray:C withInt:0];
    len += [((LibOrgBouncycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) doFinalWithByteArray:C withInt:len];
  }
  IOSByteArray *P2 = [((LibOrgBouncycastleCryptoParamsIESParameters *) nil_chk(self->param_)) getEncodingV];
  IOSByteArray *L2 = nil;
  if (((IOSByteArray *) nil_chk(self->V_))->size_ != 0) {
    L2 = [self getLengthTagWithByteArray:P2];
  }
  IOSByteArray *T = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) getMacSize]];
  [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) init__WithLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_(K2)];
  [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) updateWithByteArray:C withInt:0 withInt:C->size_];
  if (P2 != nil) {
    [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) updateWithByteArray:P2 withInt:0 withInt:P2->size_];
  }
  if (((IOSByteArray *) nil_chk(self->V_))->size_ != 0) {
    [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) updateWithByteArray:L2 withInt:0 withInt:((IOSByteArray *) nil_chk(L2))->size_];
  }
  [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) doFinalWithByteArray:T withInt:0];
  IOSByteArray *Output = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(self->V_))->size_ + len + T->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->V_, 0, Output, 0, self->V_->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(C, 0, Output, ((IOSByteArray *) nil_chk(self->V_))->size_, len);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(T, 0, Output, ((IOSByteArray *) nil_chk(self->V_))->size_ + len, T->size_);
  return Output;
}

IOSByteArray *LibOrgBouncycastleCryptoEnginesIESEngine_decryptBlockWithByteArray_withInt_withInt_(LibOrgBouncycastleCryptoEnginesIESEngine *self, IOSByteArray *in_enc, jint inOff, jint inLen) {
  IOSByteArray *M;
  IOSByteArray *K;
  IOSByteArray *K1;
  IOSByteArray *K2;
  jint len = 0;
  if (inLen < ((IOSByteArray *) nil_chk(self->V_))->size_ + [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) getMacSize]) {
    @throw new_LibOrgBouncycastleCryptoInvalidCipherTextException_initWithNSString_(@"Length of input must be greater than the MAC and V combined");
  }
  if (self->cipher_ == nil) {
    K1 = [IOSByteArray newArrayWithLength:inLen - ((IOSByteArray *) nil_chk(self->V_))->size_ - [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) getMacSize]];
    K2 = [IOSByteArray newArrayWithLength:[((LibOrgBouncycastleCryptoParamsIESParameters *) nil_chk(self->param_)) getMacKeySize] / 8];
    K = [IOSByteArray newArrayWithLength:K1->size_ + K2->size_];
    [((id<LibOrgBouncycastleCryptoDerivationFunction>) nil_chk(self->kdf_)) generateBytesWithByteArray:K withInt:0 withInt:K->size_];
    if (((IOSByteArray *) nil_chk(self->V_))->size_ != 0) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, 0, K2, 0, K2->size_);
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, K2->size_, K1, 0, K1->size_);
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, 0, K1, 0, K1->size_);
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, K1->size_, K2, 0, K2->size_);
    }
    M = [IOSByteArray newArrayWithLength:K1->size_];
    for (jint i = 0; i != K1->size_; i++) {
      *IOSByteArray_GetRef(M, i) = (jbyte) (IOSByteArray_Get(nil_chk(in_enc), inOff + ((IOSByteArray *) nil_chk(self->V_))->size_ + i) ^ IOSByteArray_Get(K1, i));
    }
  }
  else {
    K1 = [IOSByteArray newArrayWithLength:[((LibOrgBouncycastleCryptoParamsIESWithCipherParameters *) nil_chk(((LibOrgBouncycastleCryptoParamsIESWithCipherParameters *) cast_chk(self->param_, [LibOrgBouncycastleCryptoParamsIESWithCipherParameters class])))) getCipherKeySize] / 8];
    K2 = [IOSByteArray newArrayWithLength:[((LibOrgBouncycastleCryptoParamsIESParameters *) nil_chk(self->param_)) getMacKeySize] / 8];
    K = [IOSByteArray newArrayWithLength:K1->size_ + K2->size_];
    [((id<LibOrgBouncycastleCryptoDerivationFunction>) nil_chk(self->kdf_)) generateBytesWithByteArray:K withInt:0 withInt:K->size_];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, 0, K1, 0, K1->size_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, K1->size_, K2, 0, K2->size_);
    id<LibOrgBouncycastleCryptoCipherParameters> cp = new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_(K1);
    if (self->IV_ != nil) {
      cp = new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(cp, self->IV_);
    }
    [((LibOrgBouncycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) init__WithBoolean:false withLibOrgBouncycastleCryptoCipherParameters:cp];
    M = [IOSByteArray newArrayWithLength:[((LibOrgBouncycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) getOutputSizeWithInt:inLen - ((IOSByteArray *) nil_chk(self->V_))->size_ - [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) getMacSize]]];
    len = [((LibOrgBouncycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) processBytesWithByteArray:in_enc withInt:inOff + ((IOSByteArray *) nil_chk(self->V_))->size_ withInt:inLen - self->V_->size_ - [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) getMacSize] withByteArray:M withInt:0];
  }
  IOSByteArray *P2 = [((LibOrgBouncycastleCryptoParamsIESParameters *) nil_chk(self->param_)) getEncodingV];
  IOSByteArray *L2 = nil;
  if (((IOSByteArray *) nil_chk(self->V_))->size_ != 0) {
    L2 = [self getLengthTagWithByteArray:P2];
  }
  jint end = inOff + inLen;
  IOSByteArray *T1 = LibOrgBouncycastleUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(in_enc, end - [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) getMacSize], end);
  IOSByteArray *T2 = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(T1))->size_];
  [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) init__WithLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_(K2)];
  [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) updateWithByteArray:in_enc withInt:inOff + ((IOSByteArray *) nil_chk(self->V_))->size_ withInt:inLen - self->V_->size_ - T2->size_];
  if (P2 != nil) {
    [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) updateWithByteArray:P2 withInt:0 withInt:P2->size_];
  }
  if (((IOSByteArray *) nil_chk(self->V_))->size_ != 0) {
    [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) updateWithByteArray:L2 withInt:0 withInt:((IOSByteArray *) nil_chk(L2))->size_];
  }
  [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->mac_)) doFinalWithByteArray:T2 withInt:0];
  if (!LibOrgBouncycastleUtilArrays_constantTimeAreEqualWithByteArray_withByteArray_(T1, T2)) {
    @throw new_LibOrgBouncycastleCryptoInvalidCipherTextException_initWithNSString_(@"invalid MAC");
  }
  if (self->cipher_ == nil) {
    return M;
  }
  else {
    len += [self->cipher_ doFinalWithByteArray:M withInt:len];
    return LibOrgBouncycastleUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(M, 0, len);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesIESEngine)