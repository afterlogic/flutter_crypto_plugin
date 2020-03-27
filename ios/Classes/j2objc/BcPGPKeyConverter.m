//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/bc/BcPGPKeyConverter.java
//

#include "ASN1Encodable.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "AlgorithmIdentifier.h"
#include "AsymmetricKeyParameter.h"
#include "BCPGKey.h"
#include "BcKeyFingerprintCalculator.h"
#include "BcPGPKeyConverter.h"
#include "BcUtil.h"
#include "DERBitString.h"
#include "DEROctetString.h"
#include "DSAParameters.h"
#include "DSAPrivateKeyParameters.h"
#include "DSAPublicBCPGKey.h"
#include "DSAPublicKeyParameters.h"
#include "DSASecretBCPGKey.h"
#include "ECCurve.h"
#include "ECDHPublicBCPGKey.h"
#include "ECDSAPublicBCPGKey.h"
#include "ECNamedCurveTable.h"
#include "ECNamedDomainParameters.h"
#include "ECPoint.h"
#include "ECPrivateKeyParameters.h"
#include "ECPublicBCPGKey.h"
#include "ECPublicKeyParameters.h"
#include "ECSecretBCPGKey.h"
#include "ElGamalParameters.h"
#include "ElGamalPrivateKeyParameters.h"
#include "ElGamalPublicBCPGKey.h"
#include "ElGamalPublicKeyParameters.h"
#include "ElGamalSecretBCPGKey.h"
#include "HashAlgorithmTags.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PGPAlgorithmParameters.h"
#include "PGPException.h"
#include "PGPKdfParameters.h"
#include "PGPPrivateKey.h"
#include "PGPPublicKey.h"
#include "PublicKeyAlgorithmTags.h"
#include "PublicKeyPacket.h"
#include "RSAKeyParameters.h"
#include "RSAPrivateCrtKeyParameters.h"
#include "RSAPublicBCPGKey.h"
#include "RSASecretBCPGKey.h"
#include "SubjectPublicKeyInfo.h"
#include "SubjectPublicKeyInfoFactory.h"
#include "SymmetricKeyAlgorithmTags.h"
#include "X9ECParameters.h"
#include "X9ECPoint.h"
#include "java/io/IOException.h"
#include "java/lang/Exception.h"
#include "java/math/BigInteger.h"
#include "java/util/Date.h"

@implementation LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPGPPublicKeyWithInt:(jint)algorithm
              withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters:(id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters>)algorithmParameters
         withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)pubKey
                                                 withJavaUtilDate:(JavaUtilDate *)time {
  id<LibOrgBouncycastleBcpgBCPGKey> bcpgKey;
  if ([pubKey isKindOfClass:[LibOrgBouncycastleCryptoParamsRSAKeyParameters class]]) {
    LibOrgBouncycastleCryptoParamsRSAKeyParameters *rK = (LibOrgBouncycastleCryptoParamsRSAKeyParameters *) pubKey;
    bcpgKey = new_LibOrgBouncycastleBcpgRSAPublicBCPGKey_initWithJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(rK)) getModulus], [rK getExponent]);
  }
  else if ([pubKey isKindOfClass:[LibOrgBouncycastleCryptoParamsDSAPublicKeyParameters class]]) {
    LibOrgBouncycastleCryptoParamsDSAPublicKeyParameters *dK = (LibOrgBouncycastleCryptoParamsDSAPublicKeyParameters *) pubKey;
    LibOrgBouncycastleCryptoParamsDSAParameters *dP = [((LibOrgBouncycastleCryptoParamsDSAPublicKeyParameters *) nil_chk(dK)) getParameters];
    bcpgKey = new_LibOrgBouncycastleBcpgDSAPublicBCPGKey_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleCryptoParamsDSAParameters *) nil_chk(dP)) getP], [dP getQ], [dP getG], [dK getY]);
  }
  else if ([pubKey isKindOfClass:[LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters class]]) {
    LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters *eK = (LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters *) pubKey;
    LibOrgBouncycastleCryptoParamsElGamalParameters *eS = [((LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters *) nil_chk(eK)) getParameters];
    bcpgKey = new_LibOrgBouncycastleBcpgElGamalPublicBCPGKey_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleCryptoParamsElGamalParameters *) nil_chk(eS)) getP], [eS getG], [eK getY]);
  }
  else if ([pubKey isKindOfClass:[LibOrgBouncycastleCryptoParamsECPublicKeyParameters class]]) {
    LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *keyInfo;
    @try {
      keyInfo = LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_createSubjectPublicKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(pubKey);
    }
    @catch (JavaIoIOException *e) {
      @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(JreStrcat("$$", @"Unable to encode key: ", [e getMessage]), e);
    }
    LibOrgBouncycastleAsn1ASN1ObjectIdentifier *curveOid = LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *) nil_chk(keyInfo)) getAlgorithm])) getParameters]);
    LibOrgBouncycastleAsn1X9X9ECParameters *params = LibOrgBouncycastleAsn1X9ECNamedCurveTable_getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(curveOid);
    LibOrgBouncycastleAsn1ASN1OctetString *key = new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_([((LibOrgBouncycastleAsn1DERBitString *) nil_chk([keyInfo getPublicKeyData])) getBytes]);
    LibOrgBouncycastleAsn1X9X9ECPoint *derQ = new_LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleAsn1ASN1OctetString_([((LibOrgBouncycastleAsn1X9X9ECParameters *) nil_chk(params)) getCurve], key);
    if (algorithm == LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDH) {
      LibOrgBouncycastleOpenpgpPGPKdfParameters *kdfParams = (LibOrgBouncycastleOpenpgpPGPKdfParameters *) cast_chk(algorithmParameters, [LibOrgBouncycastleOpenpgpPGPKdfParameters class]);
      if (kdfParams == nil) {
        kdfParams = new_LibOrgBouncycastleOpenpgpPGPKdfParameters_initWithInt_withInt_(LibOrgBouncycastleBcpgHashAlgorithmTags_SHA256, LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags_AES_128);
      }
      bcpgKey = new_LibOrgBouncycastleBcpgECDHPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECPoint_withInt_withInt_(curveOid, [derQ getPoint], [kdfParams getHashAlgorithm], [kdfParams getSymmetricWrapAlgorithm]);
    }
    else if (algorithm == LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDSA) {
      bcpgKey = new_LibOrgBouncycastleBcpgECDSAPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECPoint_(curveOid, [derQ getPoint]);
    }
    else {
      @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"unknown EC algorithm");
    }
  }
  else {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"unknown key class");
  }
  return new_LibOrgBouncycastleOpenpgpPGPPublicKey_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(new_LibOrgBouncycastleBcpgPublicKeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(algorithm, time, bcpgKey), new_LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator_init());
}

- (LibOrgBouncycastleOpenpgpPGPPrivateKey *)getPGPPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey
                                             withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privKey {
  id<LibOrgBouncycastleBcpgBCPGKey> privPk;
  {
    LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters *rsK;
    LibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters *dsK;
    LibOrgBouncycastleCryptoParamsElGamalPrivateKeyParameters *esK;
    LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *ecK;
    switch ([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(pubKey)) getAlgorithm]) {
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_ENCRYPT:
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_SIGN:
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_GENERAL:
      rsK = (LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters *) cast_chk(privKey, [LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters class]);
      privPk = new_LibOrgBouncycastleBcpgRSASecretBCPGKey_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters *) nil_chk(rsK)) getExponent], [rsK getP], [rsK getQ]);
      break;
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_DSA:
      dsK = (LibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters *) cast_chk(privKey, [LibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters class]);
      privPk = new_LibOrgBouncycastleBcpgDSASecretBCPGKey_initWithJavaMathBigInteger_([((LibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters *) nil_chk(dsK)) getX]);
      break;
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_ENCRYPT:
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_GENERAL:
      esK = (LibOrgBouncycastleCryptoParamsElGamalPrivateKeyParameters *) cast_chk(privKey, [LibOrgBouncycastleCryptoParamsElGamalPrivateKeyParameters class]);
      privPk = new_LibOrgBouncycastleBcpgElGamalSecretBCPGKey_initWithJavaMathBigInteger_([((LibOrgBouncycastleCryptoParamsElGamalPrivateKeyParameters *) nil_chk(esK)) getX]);
      break;
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDH:
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDSA:
      ecK = (LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) cast_chk(privKey, [LibOrgBouncycastleCryptoParamsECPrivateKeyParameters class]);
      privPk = new_LibOrgBouncycastleBcpgECSecretBCPGKey_initWithJavaMathBigInteger_([((LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) nil_chk(ecK)) getD]);
      break;
      default:
      @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"unknown key class");
    }
  }
  return new_LibOrgBouncycastleOpenpgpPGPPrivateKey_initWithLong_withLibOrgBouncycastleBcpgPublicKeyPacket_withLibOrgBouncycastleBcpgBCPGKey_([pubKey getKeyID], [pubKey getPublicKeyPacket], privPk);
}

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)publicKey {
  LibOrgBouncycastleBcpgPublicKeyPacket *publicPk = [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(publicKey)) getPublicKeyPacket];
  @try {
    {
      LibOrgBouncycastleBcpgRSAPublicBCPGKey *rsaK;
      LibOrgBouncycastleBcpgDSAPublicBCPGKey *dsaK;
      LibOrgBouncycastleBcpgElGamalPublicBCPGKey *elK;
      LibOrgBouncycastleBcpgECPublicBCPGKey *ecPub;
      LibOrgBouncycastleAsn1X9X9ECParameters *x9;
      switch ([((LibOrgBouncycastleBcpgPublicKeyPacket *) nil_chk(publicPk)) getAlgorithm]) {
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_ENCRYPT:
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_GENERAL:
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_SIGN:
        rsaK = (LibOrgBouncycastleBcpgRSAPublicBCPGKey *) cast_chk([publicPk getKey], [LibOrgBouncycastleBcpgRSAPublicBCPGKey class]);
        return new_LibOrgBouncycastleCryptoParamsRSAKeyParameters_initWithBoolean_withJavaMathBigInteger_withJavaMathBigInteger_(false, [((LibOrgBouncycastleBcpgRSAPublicBCPGKey *) nil_chk(rsaK)) getModulus], [rsaK getPublicExponent]);
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_DSA:
        dsaK = (LibOrgBouncycastleBcpgDSAPublicBCPGKey *) cast_chk([publicPk getKey], [LibOrgBouncycastleBcpgDSAPublicBCPGKey class]);
        return new_LibOrgBouncycastleCryptoParamsDSAPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDSAParameters_([((LibOrgBouncycastleBcpgDSAPublicBCPGKey *) nil_chk(dsaK)) getY], new_LibOrgBouncycastleCryptoParamsDSAParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([dsaK getP], [dsaK getQ], [dsaK getG]));
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_ENCRYPT:
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_GENERAL:
        elK = (LibOrgBouncycastleBcpgElGamalPublicBCPGKey *) cast_chk([publicPk getKey], [LibOrgBouncycastleBcpgElGamalPublicBCPGKey class]);
        return new_LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsElGamalParameters_([((LibOrgBouncycastleBcpgElGamalPublicBCPGKey *) nil_chk(elK)) getY], new_LibOrgBouncycastleCryptoParamsElGamalParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_([elK getP], [elK getG]));
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDH:
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDSA:
        ecPub = (LibOrgBouncycastleBcpgECPublicBCPGKey *) cast_chk([publicPk getKey], [LibOrgBouncycastleBcpgECPublicBCPGKey class]);
        x9 = LibOrgBouncycastleOpenpgpOperatorBcBcUtil_getX9ParametersWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_([((LibOrgBouncycastleBcpgECPublicBCPGKey *) nil_chk(ecPub)) getCurveOID]);
        return new_LibOrgBouncycastleCryptoParamsECPublicKeyParameters_initWithLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleCryptoParamsECDomainParameters_(LibOrgBouncycastleOpenpgpOperatorBcBcUtil_decodePointWithJavaMathBigInteger_withLibOrgBouncycastleMathEcECCurve_([ecPub getEncodedPoint], [((LibOrgBouncycastleAsn1X9X9ECParameters *) nil_chk(x9)) getCurve]), new_LibOrgBouncycastleCryptoParamsECNamedDomainParameters_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_([ecPub getCurveOID], [x9 getCurve], [x9 getG], [x9 getN], [x9 getH]));
        default:
        @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"unknown public key algorithm encountered");
      }
    }
  }
  @catch (LibOrgBouncycastleOpenpgpPGPException *e) {
    @throw e;
  }
  @catch (JavaLangException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(@"exception constructing public key", e);
  }
}

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPrivateKey:(LibOrgBouncycastleOpenpgpPGPPrivateKey *)privKey {
  LibOrgBouncycastleBcpgPublicKeyPacket *pubPk = [((LibOrgBouncycastleOpenpgpPGPPrivateKey *) nil_chk(privKey)) getPublicKeyPacket];
  id<LibOrgBouncycastleBcpgBCPGKey> privPk = [privKey getPrivateKeyDataPacket];
  @try {
    {
      LibOrgBouncycastleBcpgRSAPublicBCPGKey *rsaPub;
      LibOrgBouncycastleBcpgRSASecretBCPGKey *rsaPriv;
      LibOrgBouncycastleBcpgDSAPublicBCPGKey *dsaPub;
      LibOrgBouncycastleBcpgDSASecretBCPGKey *dsaPriv;
      LibOrgBouncycastleBcpgElGamalPublicBCPGKey *elPub;
      LibOrgBouncycastleBcpgElGamalSecretBCPGKey *elPriv;
      LibOrgBouncycastleBcpgECPublicBCPGKey *ecPub;
      LibOrgBouncycastleBcpgECSecretBCPGKey *ecPriv;
      LibOrgBouncycastleAsn1X9X9ECParameters *x9;
      switch ([((LibOrgBouncycastleBcpgPublicKeyPacket *) nil_chk(pubPk)) getAlgorithm]) {
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_ENCRYPT:
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_GENERAL:
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_SIGN:
        rsaPub = (LibOrgBouncycastleBcpgRSAPublicBCPGKey *) cast_chk([pubPk getKey], [LibOrgBouncycastleBcpgRSAPublicBCPGKey class]);
        rsaPriv = (LibOrgBouncycastleBcpgRSASecretBCPGKey *) cast_chk(privPk, [LibOrgBouncycastleBcpgRSASecretBCPGKey class]);
        return new_LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleBcpgRSASecretBCPGKey *) nil_chk(rsaPriv)) getModulus], [((LibOrgBouncycastleBcpgRSAPublicBCPGKey *) nil_chk(rsaPub)) getPublicExponent], [rsaPriv getPrivateExponent], [rsaPriv getPrimeP], [rsaPriv getPrimeQ], [rsaPriv getPrimeExponentP], [rsaPriv getPrimeExponentQ], [rsaPriv getCrtCoefficient]);
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_DSA:
        dsaPub = (LibOrgBouncycastleBcpgDSAPublicBCPGKey *) cast_chk([pubPk getKey], [LibOrgBouncycastleBcpgDSAPublicBCPGKey class]);
        dsaPriv = (LibOrgBouncycastleBcpgDSASecretBCPGKey *) cast_chk(privPk, [LibOrgBouncycastleBcpgDSASecretBCPGKey class]);
        return new_LibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDSAParameters_([((LibOrgBouncycastleBcpgDSASecretBCPGKey *) nil_chk(dsaPriv)) getX], new_LibOrgBouncycastleCryptoParamsDSAParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleBcpgDSAPublicBCPGKey *) nil_chk(dsaPub)) getP], [dsaPub getQ], [dsaPub getG]));
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_ENCRYPT:
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_GENERAL:
        elPub = (LibOrgBouncycastleBcpgElGamalPublicBCPGKey *) cast_chk([pubPk getKey], [LibOrgBouncycastleBcpgElGamalPublicBCPGKey class]);
        elPriv = (LibOrgBouncycastleBcpgElGamalSecretBCPGKey *) cast_chk(privPk, [LibOrgBouncycastleBcpgElGamalSecretBCPGKey class]);
        return new_LibOrgBouncycastleCryptoParamsElGamalPrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsElGamalParameters_([((LibOrgBouncycastleBcpgElGamalSecretBCPGKey *) nil_chk(elPriv)) getX], new_LibOrgBouncycastleCryptoParamsElGamalParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleBcpgElGamalPublicBCPGKey *) nil_chk(elPub)) getP], [elPub getG]));
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDH:
        case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDSA:
        ecPub = (LibOrgBouncycastleBcpgECPublicBCPGKey *) cast_chk([pubPk getKey], [LibOrgBouncycastleBcpgECPublicBCPGKey class]);
        ecPriv = (LibOrgBouncycastleBcpgECSecretBCPGKey *) cast_chk(privPk, [LibOrgBouncycastleBcpgECSecretBCPGKey class]);
        x9 = LibOrgBouncycastleOpenpgpOperatorBcBcUtil_getX9ParametersWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_([((LibOrgBouncycastleBcpgECPublicBCPGKey *) nil_chk(ecPub)) getCurveOID]);
        return new_LibOrgBouncycastleCryptoParamsECPrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsECDomainParameters_([((LibOrgBouncycastleBcpgECSecretBCPGKey *) nil_chk(ecPriv)) getX], new_LibOrgBouncycastleCryptoParamsECNamedDomainParameters_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_([ecPub getCurveOID], [((LibOrgBouncycastleAsn1X9X9ECParameters *) nil_chk(x9)) getCurve], [x9 getG], [x9 getN], [x9 getH]));
        default:
        @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"unknown public key algorithm encountered");
      }
    }
  }
  @catch (LibOrgBouncycastleOpenpgpPGPException *e) {
    @throw e;
  }
  @catch (JavaLangException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(@"Exception constructing key", e);
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKey;", 0x1, 0, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPrivateKey;", 0x1, 3, 4, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x1, 5, 6, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x1, 7, 8, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getPGPPublicKeyWithInt:withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters:withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:withJavaUtilDate:);
  methods[2].selector = @selector(getPGPPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:);
  methods[3].selector = @selector(getPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[4].selector = @selector(getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPrivateKey:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "getPGPPublicKey", "ILLibOrgBouncycastleOpenpgpPGPAlgorithmParameters;LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;LJavaUtilDate;", "LLibOrgBouncycastleOpenpgpPGPException;", "getPGPPrivateKey", "LLibOrgBouncycastleOpenpgpPGPPublicKey;LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", "getPublicKey", "LLibOrgBouncycastleOpenpgpPGPPublicKey;", "getPrivateKey", "LLibOrgBouncycastleOpenpgpPGPPrivateKey;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter = { "BcPGPKeyConverter", "lib.org.bouncycastle.openpgp.operator.bc", ptrTable, methods, NULL, 7, 0x1, 5, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter;
}

@end

void LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter_init(LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter *self) {
  NSObject_init(self);
}

LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter *new_LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter, init)
}

LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter *create_LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyConverter)
