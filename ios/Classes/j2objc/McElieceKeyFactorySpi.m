//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/mceliece/McElieceKeyFactorySpi.java
//

#include "ASN1Encodable.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "AlgorithmIdentifier.h"
#include "BCMcEliecePrivateKey.h"
#include "BCMcEliecePublicKey.h"
#include "Digest.h"
#include "GF2Matrix.h"
#include "GF2mField.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "McElieceKeyFactorySpi.h"
#include "McEliecePrivateKey.h"
#include "McEliecePrivateKeyParameters.h"
#include "McEliecePublicKey.h"
#include "McEliecePublicKeyParameters.h"
#include "PQCObjectIdentifiers.h"
#include "Permutation.h"
#include "PolynomialGF2mSmallM.h"
#include "PrivateKeyInfo.h"
#include "SHA256Digest.h"
#include "SubjectPublicKeyInfo.h"
#include "java/io/IOException.h"
#include "java/security/InvalidKeyException.h"
#include "java/security/Key.h"
#include "java/security/KeyFactorySpi.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"
#include "java/security/spec/InvalidKeySpecException.h"
#include "java/security/spec/KeySpec.h"
#include "java/security/spec/PKCS8EncodedKeySpec.h"
#include "java/security/spec/X509EncodedKeySpec.h"

@interface LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi ()

+ (id<LibOrgBouncycastleCryptoDigest>)getDigestWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)algId;

@end

__attribute__((unused)) static id<LibOrgBouncycastleCryptoDigest> LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_getDigestWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId);

NSString *LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_OID = @"1.3.6.1.4.1.8301.3.1.3.4.1";

@implementation LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi

+ (NSString *)OID {
  return LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_OID;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id<JavaSecurityPublicKey>)engineGeneratePublicWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec {
  if ([keySpec isKindOfClass:[JavaSecuritySpecX509EncodedKeySpec class]]) {
    IOSByteArray *encKey = [((JavaSecuritySpecX509EncodedKeySpec *) nil_chk(((JavaSecuritySpecX509EncodedKeySpec *) keySpec))) getEncoded];
    LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *pki;
    @try {
      pki = LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_(encKey));
    }
    @catch (JavaIoIOException *e) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_([e description]);
    }
    @try {
      if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, mcEliece))) isEqual:[((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *) nil_chk(pki)) getAlgorithm])) getAlgorithm]]) {
        LibOrgBouncycastlePqcAsn1McEliecePublicKey *key = LibOrgBouncycastlePqcAsn1McEliecePublicKey_getInstanceWithId_([pki parsePublicKey]);
        return new_LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePublicKey_initWithLibOrgBouncycastlePqcCryptoMcelieceMcEliecePublicKeyParameters_(new_LibOrgBouncycastlePqcCryptoMcelieceMcEliecePublicKeyParameters_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_([((LibOrgBouncycastlePqcAsn1McEliecePublicKey *) nil_chk(key)) getN], [key getT], [key getG]));
      }
      else {
        @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(@"Unable to recognise OID in McEliece public key");
      }
    }
    @catch (JavaIoIOException *cce) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$$", @"Unable to decode X509EncodedKeySpec: ", [cce getMessage]));
    }
  }
  @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$@C", @"Unsupported key specification: ", [((id<JavaSecuritySpecKeySpec>) nil_chk(keySpec)) java_getClass], '.'));
}

- (id<JavaSecurityPrivateKey>)engineGeneratePrivateWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec {
  if ([keySpec isKindOfClass:[JavaSecuritySpecPKCS8EncodedKeySpec class]]) {
    IOSByteArray *encKey = [((JavaSecuritySpecPKCS8EncodedKeySpec *) nil_chk(((JavaSecuritySpecPKCS8EncodedKeySpec *) keySpec))) getEncoded];
    LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *pki;
    @try {
      pki = LibOrgBouncycastleAsn1PkcsPrivateKeyInfo_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_(encKey));
    }
    @catch (JavaIoIOException *e) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$@", @"Unable to decode PKCS8EncodedKeySpec: ", e));
    }
    @try {
      if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, mcEliece))) isEqual:[((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *) nil_chk(pki)) getPrivateKeyAlgorithm])) getAlgorithm]]) {
        LibOrgBouncycastlePqcAsn1McEliecePrivateKey *key = LibOrgBouncycastlePqcAsn1McEliecePrivateKey_getInstanceWithId_([pki parsePrivateKey]);
        return new_LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePrivateKey_initWithLibOrgBouncycastlePqcCryptoMcelieceMcEliecePrivateKeyParameters_(new_LibOrgBouncycastlePqcCryptoMcelieceMcEliecePrivateKeyParameters_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2mField_withLibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM_withLibOrgBouncycastlePqcMathLinearalgebraPermutation_withLibOrgBouncycastlePqcMathLinearalgebraPermutation_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_([((LibOrgBouncycastlePqcAsn1McEliecePrivateKey *) nil_chk(key)) getN], [key getK], [key getField], [key getGoppaPoly], [key getP1], [key getP2], [key getSInv]));
      }
      else {
        @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(@"Unable to recognise OID in McEliece private key");
      }
    }
    @catch (JavaIoIOException *cce) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(@"Unable to decode PKCS8EncodedKeySpec.");
    }
  }
  @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$@C", @"Unsupported key specification: ", [((id<JavaSecuritySpecKeySpec>) nil_chk(keySpec)) java_getClass], '.'));
}

- (id<JavaSecuritySpecKeySpec>)getKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                withIOSClass:(IOSClass *)keySpec {
  if ([key isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePrivateKey class]]) {
    if ([JavaSecuritySpecPKCS8EncodedKeySpec_class_() isAssignableFrom:keySpec]) {
      return new_JavaSecuritySpecPKCS8EncodedKeySpec_initWithByteArray_([((id<JavaSecurityKey>) nil_chk(key)) getEncoded]);
    }
  }
  else if ([key isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePublicKey class]]) {
    if ([JavaSecuritySpecX509EncodedKeySpec_class_() isAssignableFrom:keySpec]) {
      return new_JavaSecuritySpecX509EncodedKeySpec_initWithByteArray_([((id<JavaSecurityKey>) nil_chk(key)) getEncoded]);
    }
  }
  else {
    @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$@C", @"Unsupported key type: ", [((id<JavaSecurityKey>) nil_chk(key)) java_getClass], '.'));
  }
  @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$@C", @"Unknown key specification: ", keySpec, '.'));
}

- (id<JavaSecurityKey>)translateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key {
  if (([key isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePrivateKey class]]) || ([key isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePublicKey class]])) {
    return key;
  }
  @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"Unsupported key type.");
}

- (id<JavaSecurityPublicKey>)generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)pki {
  LibOrgBouncycastleAsn1ASN1Primitive *innerType = [((LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *) nil_chk(pki)) parsePublicKey];
  LibOrgBouncycastlePqcAsn1McEliecePublicKey *key = LibOrgBouncycastlePqcAsn1McEliecePublicKey_getInstanceWithId_(innerType);
  return new_LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePublicKey_initWithLibOrgBouncycastlePqcCryptoMcelieceMcEliecePublicKeyParameters_(new_LibOrgBouncycastlePqcCryptoMcelieceMcEliecePublicKeyParameters_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_([((LibOrgBouncycastlePqcAsn1McEliecePublicKey *) nil_chk(key)) getN], [key getT], [key getG]));
}

- (id<JavaSecurityPrivateKey>)generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)pki {
  LibOrgBouncycastleAsn1ASN1Primitive *innerType = [((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk([((LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *) nil_chk(pki)) parsePrivateKey])) toASN1Primitive];
  LibOrgBouncycastlePqcAsn1McEliecePrivateKey *key = LibOrgBouncycastlePqcAsn1McEliecePrivateKey_getInstanceWithId_(innerType);
  return new_LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePrivateKey_initWithLibOrgBouncycastlePqcCryptoMcelieceMcEliecePrivateKeyParameters_(new_LibOrgBouncycastlePqcCryptoMcelieceMcEliecePrivateKeyParameters_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2mField_withLibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM_withLibOrgBouncycastlePqcMathLinearalgebraPermutation_withLibOrgBouncycastlePqcMathLinearalgebraPermutation_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_([((LibOrgBouncycastlePqcAsn1McEliecePrivateKey *) nil_chk(key)) getN], [key getK], [key getField], [key getGoppaPoly], [key getP1], [key getP2], [key getSInv]));
}

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                      withIOSClass:(IOSClass *)tClass {
  return nil;
}

- (id<JavaSecurityKey>)engineTranslateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key {
  return nil;
}

+ (id<LibOrgBouncycastleCryptoDigest>)getDigestWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)algId {
  return LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_getDigestWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(algId);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityPublicKey;", 0x4, 0, 1, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x4, 3, 1, 2, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecKeySpec;", 0x1, 4, 5, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityKey;", 0x1, 6, 7, 8, -1, -1, -1 },
    { NULL, "LJavaSecurityPublicKey;", 0x1, 9, 10, 11, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x1, 12, 13, 11, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecKeySpec;", 0x4, 14, 5, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityKey;", 0x4, 15, 7, 8, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoDigest;", 0xa, 16, 17, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineGeneratePublicWithJavaSecuritySpecKeySpec:);
  methods[2].selector = @selector(engineGeneratePrivateWithJavaSecuritySpecKeySpec:);
  methods[3].selector = @selector(getKeySpecWithJavaSecurityKey:withIOSClass:);
  methods[4].selector = @selector(translateKeyWithJavaSecurityKey:);
  methods[5].selector = @selector(generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:);
  methods[6].selector = @selector(generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:);
  methods[7].selector = @selector(engineGetKeySpecWithJavaSecurityKey:withIOSClass:);
  methods[8].selector = @selector(engineTranslateKeyWithJavaSecurityKey:);
  methods[9].selector = @selector(getDigestWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "OID", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 18, -1, -1 },
  };
  static const void *ptrTable[] = { "engineGeneratePublic", "LJavaSecuritySpecKeySpec;", "LJavaSecuritySpecInvalidKeySpecException;", "engineGeneratePrivate", "getKeySpec", "LJavaSecurityKey;LIOSClass;", "translateKey", "LJavaSecurityKey;", "LJavaSecurityInvalidKeyException;", "generatePublic", "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;", "LJavaIoIOException;", "generatePrivate", "LLibOrgBouncycastleAsn1PkcsPrivateKeyInfo;", "engineGetKeySpec", "engineTranslateKey", "getDigest", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", &LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_OID };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi = { "McElieceKeyFactorySpi", "lib.org.bouncycastle.pqc.jcajce.provider.mceliece", ptrTable, methods, fields, 7, 0x1, 10, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi;
}

@end

void LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_init(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi *self) {
  JavaSecurityKeyFactorySpi_init(self);
}

LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi *new_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi, init)
}

LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi *create_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi, init)
}

id<LibOrgBouncycastleCryptoDigest> LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_getDigestWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId) {
  LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_initialize();
  return new_LibOrgBouncycastleCryptoDigestsSHA256Digest_init();
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi)