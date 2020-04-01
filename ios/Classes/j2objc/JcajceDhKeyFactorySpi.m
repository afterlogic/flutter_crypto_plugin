//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/dh/JcajceDhKeyFactorySpi.java
//

#include "ASN1ObjectIdentifier.h"
#include "AlgorithmIdentifier.h"
#include "BCDHPrivateKey.h"
#include "BCDHPublicKey.h"
#include "BaseKeyFactorySpi.h"
#include "ExtendedInvalidKeySpecException.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "JcajceDhKeyFactorySpi.h"
#include "PKCSObjectIdentifiers.h"
#include "PrivateKeyInfo.h"
#include "SubjectPublicKeyInfo.h"
#include "X9ObjectIdentifiers.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "java/security/InvalidKeyException.h"
#include "java/security/Key.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"
#include "java/security/spec/KeySpec.h"
#include "javax/crypto/interfaces/DHPrivateKey.h"
#include "javax/crypto/interfaces/DHPublicKey.h"
#include "javax/crypto/spec/DHParameterSpec.h"
#include "javax/crypto/spec/DHPrivateKeySpec.h"
#include "javax/crypto/spec/DHPublicKeySpec.h"

@implementation LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                      withIOSClass:(IOSClass *)spec {
  if ([((IOSClass *) nil_chk(spec)) isAssignableFrom:JavaxCryptoSpecDHPrivateKeySpec_class_()] && [JavaxCryptoInterfacesDHPrivateKey_class_() isInstance:key]) {
    id<JavaxCryptoInterfacesDHPrivateKey> k = (id<JavaxCryptoInterfacesDHPrivateKey>) cast_check(key, JavaxCryptoInterfacesDHPrivateKey_class_());
    return new_JavaxCryptoSpecDHPrivateKeySpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([((id<JavaxCryptoInterfacesDHPrivateKey>) nil_chk(k)) getX], [((JavaxCryptoSpecDHParameterSpec *) nil_chk([k getParams])) getP], [((JavaxCryptoSpecDHParameterSpec *) nil_chk([k getParams])) getG]);
  }
  else if ([spec isAssignableFrom:JavaxCryptoSpecDHPublicKeySpec_class_()] && [JavaxCryptoInterfacesDHPublicKey_class_() isInstance:key]) {
    id<JavaxCryptoInterfacesDHPublicKey> k = (id<JavaxCryptoInterfacesDHPublicKey>) cast_check(key, JavaxCryptoInterfacesDHPublicKey_class_());
    return new_JavaxCryptoSpecDHPublicKeySpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([((id<JavaxCryptoInterfacesDHPublicKey>) nil_chk(k)) getY], [((JavaxCryptoSpecDHParameterSpec *) nil_chk([k getParams])) getP], [((JavaxCryptoSpecDHParameterSpec *) nil_chk([k getParams])) getG]);
  }
  return [super engineGetKeySpecWithJavaSecurityKey:key withIOSClass:spec];
}

- (id<JavaSecurityKey>)engineTranslateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key {
  if ([JavaxCryptoInterfacesDHPublicKey_class_() isInstance:key]) {
    return new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaxCryptoInterfacesDHPublicKey_((id<JavaxCryptoInterfacesDHPublicKey>) cast_check(key, JavaxCryptoInterfacesDHPublicKey_class_()));
  }
  else if ([JavaxCryptoInterfacesDHPrivateKey_class_() isInstance:key]) {
    return new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithJavaxCryptoInterfacesDHPrivateKey_((id<JavaxCryptoInterfacesDHPrivateKey>) cast_check(key, JavaxCryptoInterfacesDHPrivateKey_class_()));
  }
  @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"key type unknown");
}

- (id<JavaSecurityPrivateKey>)engineGeneratePrivateWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec {
  if ([keySpec isKindOfClass:[JavaxCryptoSpecDHPrivateKeySpec class]]) {
    return new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithJavaxCryptoSpecDHPrivateKeySpec_((JavaxCryptoSpecDHPrivateKeySpec *) keySpec);
  }
  return [super engineGeneratePrivateWithJavaSecuritySpecKeySpec:keySpec];
}

- (id<JavaSecurityPublicKey>)engineGeneratePublicWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec {
  if ([keySpec isKindOfClass:[JavaxCryptoSpecDHPublicKeySpec class]]) {
    @try {
      return new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaxCryptoSpecDHPublicKeySpec_((JavaxCryptoSpecDHPublicKeySpec *) keySpec);
    }
    @catch (JavaLangIllegalArgumentException *e) {
      @throw new_LibOrgBouncycastleJcajceProviderAsymmetricUtilExtendedInvalidKeySpecException_initWithNSString_withJavaLangThrowable_([e getMessage], e);
    }
  }
  return [super engineGeneratePublicWithJavaSecuritySpecKeySpec:keySpec];
}

- (id<JavaSecurityPrivateKey>)generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)keyInfo {
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *algOid = [((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *) nil_chk(keyInfo)) getPrivateKeyAlgorithm])) getAlgorithm];
  if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(algOid)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, dhKeyAgreement)]) {
    return new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(keyInfo);
  }
  else if ([algOid isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, dhpublicnumber)]) {
    return new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(keyInfo);
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$@$", @"algorithm identifier ", algOid, @" in key not recognised"));
  }
}

- (id<JavaSecurityPublicKey>)generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)keyInfo {
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *algOid = [((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *) nil_chk(keyInfo)) getAlgorithm])) getAlgorithm];
  if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(algOid)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, dhKeyAgreement)]) {
    return new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(keyInfo);
  }
  else if ([algOid isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, dhpublicnumber)]) {
    return new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(keyInfo);
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$@$", @"algorithm identifier ", algOid, @" in key not recognised"));
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecKeySpec;", 0x4, 0, 1, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityKey;", 0x4, 3, 4, 5, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x4, 6, 7, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityPublicKey;", 0x4, 8, 7, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x1, 9, 10, 11, -1, -1, -1 },
    { NULL, "LJavaSecurityPublicKey;", 0x1, 12, 13, 11, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineGetKeySpecWithJavaSecurityKey:withIOSClass:);
  methods[2].selector = @selector(engineTranslateKeyWithJavaSecurityKey:);
  methods[3].selector = @selector(engineGeneratePrivateWithJavaSecuritySpecKeySpec:);
  methods[4].selector = @selector(engineGeneratePublicWithJavaSecuritySpecKeySpec:);
  methods[5].selector = @selector(generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:);
  methods[6].selector = @selector(generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "engineGetKeySpec", "LJavaSecurityKey;LIOSClass;", "LJavaSecuritySpecInvalidKeySpecException;", "engineTranslateKey", "LJavaSecurityKey;", "LJavaSecurityInvalidKeyException;", "engineGeneratePrivate", "LJavaSecuritySpecKeySpec;", "engineGeneratePublic", "generatePrivate", "LLibOrgBouncycastleAsn1PkcsPrivateKeyInfo;", "LJavaIoIOException;", "generatePublic", "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi = { "JcajceDhKeyFactorySpi", "lib.org.bouncycastle.jcajce.provider.asymmetric.dh", ptrTable, methods, NULL, 7, 0x1, 7, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi_init(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseKeyFactorySpi_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi *new_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi *create_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi)