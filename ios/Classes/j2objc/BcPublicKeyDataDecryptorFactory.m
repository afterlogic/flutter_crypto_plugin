//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/bc/BcPublicKeyDataDecryptorFactory.java
//

#include "ASN1ObjectIdentifier.h"
#include "AsymmetricBlockCipher.h"
#include "AsymmetricKeyParameter.h"
#include "BCPGKey.h"
#include "BcImplProvider.h"
#include "BcKeyFingerprintCalculator.h"
#include "BcPGPDigestCalculatorProvider.h"
#include "BcPGPKeyConverter.h"
#include "BcPublicKeyDataDecryptorFactory.h"
#include "BcUtil.h"
#include "BlockCipher.h"
#include "BufferedAsymmetricBlockCipher.h"
#include "ECCurve.h"
#include "ECDHPublicBCPGKey.h"
#include "ECNamedCurveTable.h"
#include "ECPoint.h"
#include "ECSecretBCPGKey.h"
#include "ElGamalParameters.h"
#include "ElGamalPrivateKeyParameters.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "InvalidCipherTextException.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "OpenPgpBcRFC6637KDFCalculator.h"
#include "PGPDataDecryptor.h"
#include "PGPDigestCalculator.h"
#include "PGPException.h"
#include "PGPPad.h"
#include "PGPPrivateKey.h"
#include "PublicKeyAlgorithmTags.h"
#include "PublicKeyPacket.h"
#include "RFC6637Utils.h"
#include "Wrapper.h"
#include "X9ECParameters.h"
#include "java/io/IOException.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory () {
 @public
  LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter *keyConverter_;
  LibOrgBouncycastleOpenpgpPGPPrivateKey *privKey_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory, keyConverter_, LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory, privKey_, LibOrgBouncycastleOpenpgpPGPPrivateKey *)

@implementation LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory

- (instancetype)initWithLibOrgBouncycastleOpenpgpPGPPrivateKey:(LibOrgBouncycastleOpenpgpPGPPrivateKey *)privKey {
  LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory_initWithLibOrgBouncycastleOpenpgpPGPPrivateKey_(self, privKey);
  return self;
}

- (IOSByteArray *)recoverSessionDataWithInt:(jint)keyAlgorithm
                             withByteArray2:(IOSObjectArray *)secKeyData {
  @try {
    if (keyAlgorithm != LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDH) {
      id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> c = LibOrgBouncycastleOpenpgpOperatorBcBcImplProvider_createPublicKeyCipherWithInt_(keyAlgorithm);
      LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *key = [((LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter *) nil_chk(keyConverter_)) getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPrivateKey:privKey_];
      LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher *c1 = new_LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_(c);
      [c1 init__WithBoolean:false withLibOrgBouncycastleCryptoCipherParameters:key];
      if (keyAlgorithm == LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_ENCRYPT || keyAlgorithm == LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_GENERAL) {
        IOSByteArray *bi = IOSObjectArray_Get(nil_chk(secKeyData), 0);
        [c1 processBytesWithByteArray:bi withInt:2 withInt:((IOSByteArray *) nil_chk(bi))->size_ - 2];
      }
      else {
        LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter *converter = new_LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter_init();
        LibOrgBouncycastleCryptoParamsElGamalPrivateKeyParameters *parms = (LibOrgBouncycastleCryptoParamsElGamalPrivateKeyParameters *) cast_chk([converter getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPrivateKey:privKey_], [LibOrgBouncycastleCryptoParamsElGamalPrivateKeyParameters class]);
        jint size = ([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsElGamalParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsElGamalPrivateKeyParameters *) nil_chk(parms)) getParameters])) getP])) bitLength] + 7) / 8;
        IOSByteArray *tmp = [IOSByteArray newArrayWithLength:size];
        IOSByteArray *bi = IOSObjectArray_Get(nil_chk(secKeyData), 0);
        if (((IOSByteArray *) nil_chk(bi))->size_ - 2 > size) {
          [c1 processBytesWithByteArray:bi withInt:3 withInt:bi->size_ - 3];
        }
        else {
          JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(bi, 2, tmp, tmp->size_ - (bi->size_ - 2), bi->size_ - 2);
          [c1 processBytesWithByteArray:tmp withInt:0 withInt:tmp->size_];
        }
        bi = IOSObjectArray_Get(secKeyData, 1);
        for (jint i = 0; i != tmp->size_; i++) {
          *IOSByteArray_GetRef(tmp, i) = 0;
        }
        if (((IOSByteArray *) nil_chk(bi))->size_ - 2 > size) {
          [c1 processBytesWithByteArray:bi withInt:3 withInt:bi->size_ - 3];
        }
        else {
          JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(bi, 2, tmp, tmp->size_ - (bi->size_ - 2), bi->size_ - 2);
          [c1 processBytesWithByteArray:tmp withInt:0 withInt:tmp->size_];
        }
      }
      return [c1 doFinal];
    }
    else {
      LibOrgBouncycastleBcpgECDHPublicBCPGKey *ecKey = (LibOrgBouncycastleBcpgECDHPublicBCPGKey *) cast_chk([((LibOrgBouncycastleBcpgPublicKeyPacket *) nil_chk([((LibOrgBouncycastleOpenpgpPGPPrivateKey *) nil_chk(privKey_)) getPublicKeyPacket])) getKey], [LibOrgBouncycastleBcpgECDHPublicBCPGKey class]);
      LibOrgBouncycastleAsn1X9X9ECParameters *x9Params = LibOrgBouncycastleAsn1X9ECNamedCurveTable_getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_([((LibOrgBouncycastleBcpgECDHPublicBCPGKey *) nil_chk(ecKey)) getCurveOID]);
      IOSByteArray *enc = IOSObjectArray_Get(nil_chk(secKeyData), 0);
      jint pLen = (((JreLShift32((IOSByteArray_Get(nil_chk(enc), 0) & (jint) 0xff), 8)) + (IOSByteArray_Get(enc, 1) & (jint) 0xff)) + 7) / 8;
      IOSByteArray *pEnc = [IOSByteArray newArrayWithLength:pLen];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(enc, 2, pEnc, 0, pLen);
      IOSByteArray *keyEnc = [IOSByteArray newArrayWithLength:IOSByteArray_Get(enc, pLen + 2)];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(enc, 2 + pLen + 1, keyEnc, 0, keyEnc->size_);
      id<LibOrgBouncycastleCryptoWrapper> c = LibOrgBouncycastleOpenpgpOperatorBcBcImplProvider_createWrapperWithInt_([ecKey getSymmetricKeyAlgorithm]);
      LibOrgBouncycastleMathEcECPoint *S = [((LibOrgBouncycastleMathEcECPoint *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk([((LibOrgBouncycastleMathEcECCurve *) nil_chk([((LibOrgBouncycastleAsn1X9X9ECParameters *) nil_chk(x9Params)) getCurve])) decodePointWithByteArray:pEnc])) multiplyWithJavaMathBigInteger:[((LibOrgBouncycastleBcpgECSecretBCPGKey *) nil_chk(((LibOrgBouncycastleBcpgECSecretBCPGKey *) cast_chk([((LibOrgBouncycastleOpenpgpPGPPrivateKey *) nil_chk(privKey_)) getPrivateKeyDataPacket], [LibOrgBouncycastleBcpgECSecretBCPGKey class])))) getX]])) normalize];
      LibOrgBouncycastleOpenpgpOperatorBcOpenPgpBcRFC6637KDFCalculator *rfc6637KDFCalculator = new_LibOrgBouncycastleOpenpgpOperatorBcOpenPgpBcRFC6637KDFCalculator_initWithLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withInt_([new_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_init() getWithInt:[ecKey getHashAlgorithm]], [ecKey getSymmetricKeyAlgorithm]);
      LibOrgBouncycastleCryptoParamsKeyParameter *key = new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_([rfc6637KDFCalculator createKeyWithLibOrgBouncycastleMathEcECPoint:S withByteArray:LibOrgBouncycastleOpenpgpOperatorRFC6637Utils_createUserKeyingMaterialWithLibOrgBouncycastleBcpgPublicKeyPacket_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_([((LibOrgBouncycastleOpenpgpPGPPrivateKey *) nil_chk(privKey_)) getPublicKeyPacket], new_LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator_init())]);
      [((id<LibOrgBouncycastleCryptoWrapper>) nil_chk(c)) init__WithBoolean:false withLibOrgBouncycastleCryptoCipherParameters:key];
      return LibOrgBouncycastleOpenpgpOperatorPGPPad_unpadSessionDataWithByteArray_([c unwrapWithByteArray:keyEnc withInt:0 withInt:keyEnc->size_]);
    }
  }
  @catch (JavaIoIOException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(JreStrcat("$$", @"exception creating user keying material: ", [e getMessage]), e);
  }
  @catch (LibOrgBouncycastleCryptoInvalidCipherTextException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(JreStrcat("$$", @"exception decrypting session info: ", [e getMessage]), e);
  }
}

- (id<LibOrgBouncycastleOpenpgpOperatorPGPDataDecryptor>)createDataDecryptorWithBoolean:(jboolean)withIntegrityPacket
                                                                                withInt:(jint)encAlgorithm
                                                                          withByteArray:(IOSByteArray *)key {
  id<LibOrgBouncycastleCryptoBlockCipher> engine = LibOrgBouncycastleOpenpgpOperatorBcBcImplProvider_createBlockCipherWithInt_(encAlgorithm);
  return LibOrgBouncycastleOpenpgpOperatorBcBcUtil_createDataDecryptorWithBoolean_withLibOrgBouncycastleCryptoBlockCipher_withByteArray_(withIntegrityPacket, engine, key);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorPGPDataDecryptor;", 0x1, 4, 5, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleOpenpgpPGPPrivateKey:);
  methods[1].selector = @selector(recoverSessionDataWithInt:withByteArray2:);
  methods[2].selector = @selector(createDataDecryptorWithBoolean:withInt:withByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "keyConverter_", "LLibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "privKey_", "LLibOrgBouncycastleOpenpgpPGPPrivateKey;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleOpenpgpPGPPrivateKey;", "recoverSessionData", "I[[B", "LLibOrgBouncycastleOpenpgpPGPException;", "createDataDecryptor", "ZI[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory = { "BcPublicKeyDataDecryptorFactory", "lib.org.bouncycastle.openpgp.operator.bc", ptrTable, methods, fields, 7, 0x1, 3, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory;
}

@end

void LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory_initWithLibOrgBouncycastleOpenpgpPGPPrivateKey_(LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory *self, LibOrgBouncycastleOpenpgpPGPPrivateKey *privKey) {
  NSObject_init(self);
  self->keyConverter_ = new_LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter_init();
  self->privKey_ = privKey;
}

LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory *new_LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory_initWithLibOrgBouncycastleOpenpgpPGPPrivateKey_(LibOrgBouncycastleOpenpgpPGPPrivateKey *privKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory, initWithLibOrgBouncycastleOpenpgpPGPPrivateKey_, privKey)
}

LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory *create_LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory_initWithLibOrgBouncycastleOpenpgpPGPPrivateKey_(LibOrgBouncycastleOpenpgpPGPPrivateKey *privKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory, initWithLibOrgBouncycastleOpenpgpPGPPrivateKey_, privKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory)