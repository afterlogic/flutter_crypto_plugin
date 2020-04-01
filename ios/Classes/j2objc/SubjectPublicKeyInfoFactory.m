//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/util/SubjectPublicKeyInfoFactory.java
//

#include "ASN1Encodable.h"
#include "ASN1Integer.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "AlgorithmIdentifier.h"
#include "AsymmetricKeyParameter.h"
#include "CryptoProObjectIdentifiers.h"
#include "DERNull.h"
#include "DEROctetString.h"
#include "DSAParameter.h"
#include "DSAParameters.h"
#include "DSAPublicKeyParameters.h"
#include "ECCurve.h"
#include "ECDomainParameters.h"
#include "ECFieldElement.h"
#include "ECGOST3410Parameters.h"
#include "ECNamedDomainParameters.h"
#include "ECPoint.h"
#include "ECPublicKeyParameters.h"
#include "Ed25519PublicKeyParameters.h"
#include "Ed448PublicKeyParameters.h"
#include "EdECObjectIdentifiers.h"
#include "GOST3410PublicKeyAlgParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PKCSObjectIdentifiers.h"
#include "RSAKeyParameters.h"
#include "RSAPublicKey.h"
#include "RosstandartObjectIdentifiers.h"
#include "SubjectPublicKeyInfo.h"
#include "SubjectPublicKeyInfoFactory.h"
#include "X25519PublicKeyParameters.h"
#include "X448PublicKeyParameters.h"
#include "X962Parameters.h"
#include "X9ECParameters.h"
#include "X9ECPoint.h"
#include "X9ObjectIdentifiers.h"
#include "java/io/IOException.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"
#include "java/util/HashSet.h"
#include "java/util/Set.h"

@interface LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory ()

- (instancetype)init;

+ (void)extractBytesWithByteArray:(IOSByteArray *)encKey
                          withInt:(jint)size
                          withInt:(jint)offSet
           withJavaMathBigInteger:(JavaMathBigInteger *)bI;

@end

inline id<JavaUtilSet> LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_get_cryptoProOids(void);
inline id<JavaUtilSet> LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_set_cryptoProOids(id<JavaUtilSet> value);
static id<JavaUtilSet> LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_cryptoProOids;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory, cryptoProOids, id<JavaUtilSet>)

__attribute__((unused)) static void LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_init(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory *self);

__attribute__((unused)) static LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory *new_LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory *create_LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_init(void);

__attribute__((unused)) static void LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_extractBytesWithByteArray_withInt_withInt_withJavaMathBigInteger_(IOSByteArray *encKey, jint size, jint offSet, JavaMathBigInteger *bI);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory)

@implementation LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)createSubjectPublicKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicKey {
  return LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_createSubjectPublicKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(publicKey);
}

+ (void)extractBytesWithByteArray:(IOSByteArray *)encKey
                          withInt:(jint)size
                          withInt:(jint)offSet
           withJavaMathBigInteger:(JavaMathBigInteger *)bI {
  LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_extractBytesWithByteArray_withInt_withInt_withJavaMathBigInteger_(encKey, size, offSet, bI);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;", 0x9, 0, 1, 2, -1, -1, -1 },
    { NULL, "V", 0xa, 3, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(createSubjectPublicKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:);
  methods[2].selector = @selector(extractBytesWithByteArray:withInt:withInt:withJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cryptoProOids", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 5, -1, -1 },
  };
  static const void *ptrTable[] = { "createSubjectPublicKeyInfo", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", "LJavaIoIOException;", "extractBytes", "[BIILJavaMathBigInteger;", &LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_cryptoProOids };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory = { "SubjectPublicKeyInfoFactory", "lib.org.bouncycastle.crypto.util", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory class]) {
    LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_cryptoProOids = new_JavaUtilHashSet_initWithInt_(5);
    {
      [LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_cryptoProOids addWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_A)];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_cryptoProOids)) addWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_B)];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_cryptoProOids)) addWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_C)];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_cryptoProOids)) addWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_XchA)];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_cryptoProOids)) addWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_XchB)];
    }
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory)
  }
}

@end

void LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_init(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory *new_LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory, init)
}

LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory *create_LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory, init)
}

LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_createSubjectPublicKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *publicKey) {
  LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_initialize();
  if ([publicKey isKindOfClass:[LibOrgBouncycastleCryptoParamsRSAKeyParameters class]]) {
    LibOrgBouncycastleCryptoParamsRSAKeyParameters *pub = (LibOrgBouncycastleCryptoParamsRSAKeyParameters *) publicKey;
    return new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, rsaEncryption), JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE)), new_LibOrgBouncycastleAsn1PkcsRSAPublicKey_initWithJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(pub)) getModulus], [pub getExponent]));
  }
  else if ([publicKey isKindOfClass:[LibOrgBouncycastleCryptoParamsDSAPublicKeyParameters class]]) {
    LibOrgBouncycastleCryptoParamsDSAPublicKeyParameters *pub = (LibOrgBouncycastleCryptoParamsDSAPublicKeyParameters *) publicKey;
    LibOrgBouncycastleAsn1X509DSAParameter *params = nil;
    LibOrgBouncycastleCryptoParamsDSAParameters *dsaParams = [((LibOrgBouncycastleCryptoParamsDSAPublicKeyParameters *) nil_chk(pub)) getParameters];
    if (dsaParams != nil) {
      params = new_LibOrgBouncycastleAsn1X509DSAParameter_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([dsaParams getP], [dsaParams getQ], [dsaParams getG]);
    }
    return new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, id_dsa), params), new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_([pub getY]));
  }
  else if ([publicKey isKindOfClass:[LibOrgBouncycastleCryptoParamsECPublicKeyParameters class]]) {
    LibOrgBouncycastleCryptoParamsECPublicKeyParameters *pub = (LibOrgBouncycastleCryptoParamsECPublicKeyParameters *) publicKey;
    LibOrgBouncycastleCryptoParamsECDomainParameters *domainParams = [((LibOrgBouncycastleCryptoParamsECPublicKeyParameters *) nil_chk(pub)) getParameters];
    id<LibOrgBouncycastleAsn1ASN1Encodable> params;
    if (domainParams == nil) {
      params = new_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1Null_(JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE));
    }
    else if ([domainParams isKindOfClass:[LibOrgBouncycastleCryptoParamsECGOST3410Parameters class]]) {
      LibOrgBouncycastleCryptoParamsECGOST3410Parameters *gostParams = (LibOrgBouncycastleCryptoParamsECGOST3410Parameters *) domainParams;
      JavaMathBigInteger *bX = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk([pub getQ])) getAffineXCoord])) toBigInteger];
      JavaMathBigInteger *bY = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk([pub getQ])) getAffineYCoord])) toBigInteger];
      params = new_LibOrgBouncycastleAsn1CryptoproGOST3410PublicKeyAlgParameters_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_([gostParams getPublicKeyParamSet], [gostParams getDigestParamSet]);
      jint encKeySize;
      jint offset;
      LibOrgBouncycastleAsn1ASN1ObjectIdentifier *algIdentifier;
      if ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_cryptoProOids)) containsWithId:[gostParams getPublicKeyParamSet]]) {
        encKeySize = 64;
        offset = 32;
        algIdentifier = JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001);
      }
      else {
        jboolean is512 = ([((JavaMathBigInteger *) nil_chk(bX)) bitLength] > 256);
        if (is512) {
          encKeySize = 128;
          offset = 64;
          algIdentifier = JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_512);
        }
        else {
          encKeySize = 64;
          offset = 32;
          algIdentifier = JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_256);
        }
      }
      IOSByteArray *encKey = [IOSByteArray newArrayWithLength:encKeySize];
      LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_extractBytesWithByteArray_withInt_withInt_withJavaMathBigInteger_(encKey, encKeySize / 2, 0, bX);
      LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_extractBytesWithByteArray_withInt_withInt_withJavaMathBigInteger_(encKey, encKeySize / 2, offset, bY);
      @try {
        return new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(algIdentifier, params), new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(encKey));
      }
      @catch (JavaIoIOException *e) {
        return nil;
      }
    }
    else if ([domainParams isKindOfClass:[LibOrgBouncycastleCryptoParamsECNamedDomainParameters class]]) {
      params = new_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_([((LibOrgBouncycastleCryptoParamsECNamedDomainParameters *) domainParams) getName]);
    }
    else {
      LibOrgBouncycastleAsn1X9X9ECParameters *ecP = new_LibOrgBouncycastleAsn1X9X9ECParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_([domainParams getCurve], [domainParams getG], [domainParams getN], [domainParams getH], [domainParams getSeed]);
      params = new_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1X9X9ECParameters_(ecP);
    }
    LibOrgBouncycastleAsn1ASN1OctetString *p = (LibOrgBouncycastleAsn1ASN1OctetString *) cast_chk([new_LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECPoint_([pub getQ]) toASN1Primitive], [LibOrgBouncycastleAsn1ASN1OctetString class]);
    return new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, id_ecPublicKey), params), [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(p)) getOctets]);
  }
  else if ([publicKey isKindOfClass:[LibOrgBouncycastleCryptoParamsX448PublicKeyParameters class]]) {
    LibOrgBouncycastleCryptoParamsX448PublicKeyParameters *key = (LibOrgBouncycastleCryptoParamsX448PublicKeyParameters *) publicKey;
    return new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_X448)), [((LibOrgBouncycastleCryptoParamsX448PublicKeyParameters *) nil_chk(key)) getEncoded]);
  }
  else if ([publicKey isKindOfClass:[LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters class]]) {
    LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters *key = (LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters *) publicKey;
    return new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_X25519)), [((LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters *) nil_chk(key)) getEncoded]);
  }
  else if ([publicKey isKindOfClass:[LibOrgBouncycastleCryptoParamsEd448PublicKeyParameters class]]) {
    LibOrgBouncycastleCryptoParamsEd448PublicKeyParameters *key = (LibOrgBouncycastleCryptoParamsEd448PublicKeyParameters *) publicKey;
    return new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_Ed448)), [((LibOrgBouncycastleCryptoParamsEd448PublicKeyParameters *) nil_chk(key)) getEncoded]);
  }
  else if ([publicKey isKindOfClass:[LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters class]]) {
    LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *key = (LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *) publicKey;
    return new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_Ed25519)), [((LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *) nil_chk(key)) getEncoded]);
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(@"key parameters not recognized");
  }
}

void LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_extractBytesWithByteArray_withInt_withInt_withJavaMathBigInteger_(IOSByteArray *encKey, jint size, jint offSet, JavaMathBigInteger *bI) {
  LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory_initialize();
  IOSByteArray *val = [((JavaMathBigInteger *) nil_chk(bI)) toByteArray];
  if (((IOSByteArray *) nil_chk(val))->size_ < size) {
    IOSByteArray *tmp = [IOSByteArray newArrayWithLength:size];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(val, 0, tmp, tmp->size_ - val->size_, val->size_);
    val = tmp;
  }
  for (jint i = 0; i != size; i++) {
    *IOSByteArray_GetRef(nil_chk(encKey), offSet + i) = IOSByteArray_Get(val, val->size_ - 1 - i);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoUtilSubjectPublicKeyInfoFactory)