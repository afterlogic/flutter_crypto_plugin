//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/util/JcaJceUtilDHUtil.java
//

#include "AsymmetricKeyParameter.h"
#include "BCDHPublicKey.h"
#include "DHParameters.h"
#include "DHPrivateKeyParameters.h"
#include "DHPublicKeyParameters.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "JcaJceUtilDHUtil.h"
#include "java/math/BigInteger.h"
#include "java/security/InvalidKeyException.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"
#include "javax/crypto/interfaces/DHPrivateKey.h"
#include "javax/crypto/interfaces/DHPublicKey.h"
#include "javax/crypto/spec/DHParameterSpec.h"

@implementation LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePublicKeyParameterWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key {
  return LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil_generatePublicKeyParameterWithJavaSecurityPublicKey_(key);
}

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePrivateKeyParameterWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key {
  return LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil_generatePrivateKeyParameterWithJavaSecurityPrivateKey_(key);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x9, 0, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x9, 3, 4, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generatePublicKeyParameterWithJavaSecurityPublicKey:);
  methods[2].selector = @selector(generatePrivateKeyParameterWithJavaSecurityPrivateKey:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "generatePublicKeyParameter", "LJavaSecurityPublicKey;", "LJavaSecurityInvalidKeyException;", "generatePrivateKeyParameter", "LJavaSecurityPrivateKey;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil = { "JcaJceUtilDHUtil", "lib.org.bouncycastle.jcajce.provider.asymmetric.util", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil_init(LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil *new_LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil *create_LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil, init)
}

LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil_generatePublicKeyParameterWithJavaSecurityPublicKey_(id<JavaSecurityPublicKey> key) {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil_initialize();
  if ([key isKindOfClass:[LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey class]]) {
    return [((LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *) nil_chk(((LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *) key))) engineGetKeyParameters];
  }
  if ([JavaxCryptoInterfacesDHPublicKey_class_() isInstance:key]) {
    id<JavaxCryptoInterfacesDHPublicKey> k = (id<JavaxCryptoInterfacesDHPublicKey>) cast_check(key, JavaxCryptoInterfacesDHPublicKey_class_());
    return new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_([((id<JavaxCryptoInterfacesDHPublicKey>) nil_chk(k)) getY], new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_([((JavaxCryptoSpecDHParameterSpec *) nil_chk([k getParams])) getP], [((JavaxCryptoSpecDHParameterSpec *) nil_chk([k getParams])) getG], nil, [((JavaxCryptoSpecDHParameterSpec *) nil_chk([k getParams])) getL]));
  }
  @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"can't identify DH public key.");
}

LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil_generatePrivateKeyParameterWithJavaSecurityPrivateKey_(id<JavaSecurityPrivateKey> key) {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil_initialize();
  if ([JavaxCryptoInterfacesDHPrivateKey_class_() isInstance:key]) {
    id<JavaxCryptoInterfacesDHPrivateKey> k = (id<JavaxCryptoInterfacesDHPrivateKey>) cast_check(key, JavaxCryptoInterfacesDHPrivateKey_class_());
    return new_LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_([((id<JavaxCryptoInterfacesDHPrivateKey>) nil_chk(k)) getX], new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_([((JavaxCryptoSpecDHParameterSpec *) nil_chk([k getParams])) getP], [((JavaxCryptoSpecDHParameterSpec *) nil_chk([k getParams])) getG], nil, [((JavaxCryptoSpecDHParameterSpec *) nil_chk([k getParams])) getL]));
  }
  @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"can't identify DH private key.");
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricUtilJcaJceUtilDHUtil)
