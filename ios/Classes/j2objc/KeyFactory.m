//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/x509/KeyFactory.java
//

#include "ASN1ObjectIdentifier.h"
#include "AlgorithmIdentifier.h"
#include "BouncyCastleProvider.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyFactory.h"
#include "PrivateKeyInfo.h"
#include "SubjectPublicKeyInfo.h"
#include "java/lang/Exception.h"
#include "java/security/InvalidKeyException.h"
#include "java/security/Key.h"
#include "java/security/KeyFactorySpi.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"
#include "java/security/spec/InvalidKeySpecException.h"
#include "java/security/spec/KeySpec.h"
#include "java/security/spec/PKCS8EncodedKeySpec.h"
#include "java/security/spec/X509EncodedKeySpec.h"

@implementation LibOrgBouncycastleJcajceProviderAsymmetricX509KeyFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricX509KeyFactory_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id<JavaSecurityPrivateKey>)engineGeneratePrivateWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec {
  if ([keySpec isKindOfClass:[JavaSecuritySpecPKCS8EncodedKeySpec class]]) {
    @try {
      LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info = LibOrgBouncycastleAsn1PkcsPrivateKeyInfo_getInstanceWithId_([((JavaSecuritySpecPKCS8EncodedKeySpec *) nil_chk(((JavaSecuritySpecPKCS8EncodedKeySpec *) keySpec))) getEncoded]);
      id<JavaSecurityPrivateKey> key = LibOrgBouncycastleJceProviderBouncyCastleProvider_getPrivateKeyWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(info);
      if (key != nil) {
        return key;
      }
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$@", @"no factory found for OID: ", [((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *) nil_chk(info)) getPrivateKeyAlgorithm])) getAlgorithm]));
    }
    @catch (JavaLangException *e) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_([e description]);
    }
  }
  @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$$", @"Unknown KeySpec type: ", [[((id<JavaSecuritySpecKeySpec>) nil_chk(keySpec)) java_getClass] getName]));
}

- (id<JavaSecurityPublicKey>)engineGeneratePublicWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec {
  if ([keySpec isKindOfClass:[JavaSecuritySpecX509EncodedKeySpec class]]) {
    @try {
      LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info = LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_getInstanceWithId_([((JavaSecuritySpecX509EncodedKeySpec *) nil_chk(((JavaSecuritySpecX509EncodedKeySpec *) keySpec))) getEncoded]);
      id<JavaSecurityPublicKey> key = LibOrgBouncycastleJceProviderBouncyCastleProvider_getPublicKeyWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(info);
      if (key != nil) {
        return key;
      }
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$@", @"no factory found for OID: ", [((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *) nil_chk(info)) getAlgorithm])) getAlgorithm]));
    }
    @catch (JavaLangException *e) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_([e description]);
    }
  }
  @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$$", @"Unknown KeySpec type: ", [[((id<JavaSecuritySpecKeySpec>) nil_chk(keySpec)) java_getClass] getName]));
}

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                      withIOSClass:(IOSClass *)keySpec {
  if ([((IOSClass *) nil_chk(keySpec)) isAssignableFrom:JavaSecuritySpecPKCS8EncodedKeySpec_class_()] && [((NSString *) nil_chk([((id<JavaSecurityKey>) nil_chk(key)) getFormat])) isEqual:@"PKCS#8"]) {
    return new_JavaSecuritySpecPKCS8EncodedKeySpec_initWithByteArray_([((id<JavaSecurityKey>) nil_chk(key)) getEncoded]);
  }
  else if ([keySpec isAssignableFrom:JavaSecuritySpecX509EncodedKeySpec_class_()] && [((NSString *) nil_chk([((id<JavaSecurityKey>) nil_chk(key)) getFormat])) isEqual:@"X.509"]) {
    return new_JavaSecuritySpecX509EncodedKeySpec_initWithByteArray_([((id<JavaSecurityKey>) nil_chk(key)) getEncoded]);
  }
  @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$@C@", @"not implemented yet ", key, ' ', keySpec));
}

- (id<JavaSecurityKey>)engineTranslateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key {
  @throw new_JavaSecurityInvalidKeyException_initWithNSString_(JreStrcat("$@", @"not implemented yet ", key));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x4, 0, 1, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityPublicKey;", 0x4, 3, 1, 2, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecKeySpec;", 0x4, 4, 5, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityKey;", 0x4, 6, 7, 8, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineGeneratePrivateWithJavaSecuritySpecKeySpec:);
  methods[2].selector = @selector(engineGeneratePublicWithJavaSecuritySpecKeySpec:);
  methods[3].selector = @selector(engineGetKeySpecWithJavaSecurityKey:withIOSClass:);
  methods[4].selector = @selector(engineTranslateKeyWithJavaSecurityKey:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "engineGeneratePrivate", "LJavaSecuritySpecKeySpec;", "LJavaSecuritySpecInvalidKeySpecException;", "engineGeneratePublic", "engineGetKeySpec", "LJavaSecurityKey;LIOSClass;", "engineTranslateKey", "LJavaSecurityKey;", "LJavaSecurityInvalidKeyException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricX509KeyFactory = { "KeyFactory", "lib.org.bouncycastle.jcajce.provider.asymmetric.x509", ptrTable, methods, NULL, 7, 0x1, 5, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricX509KeyFactory;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricX509KeyFactory_init(LibOrgBouncycastleJcajceProviderAsymmetricX509KeyFactory *self) {
  JavaSecurityKeyFactorySpi_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricX509KeyFactory *new_LibOrgBouncycastleJcajceProviderAsymmetricX509KeyFactory_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509KeyFactory, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricX509KeyFactory *create_LibOrgBouncycastleJcajceProviderAsymmetricX509KeyFactory_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509KeyFactory, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricX509KeyFactory)
