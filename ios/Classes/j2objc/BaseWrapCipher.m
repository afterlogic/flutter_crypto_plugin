//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/util/BaseWrapCipher.java
//

#include "ASN1ObjectIdentifier.h"
#include "AlgorithmIdentifier.h"
#include "Arrays.h"
#include "BCJcaJceHelper.h"
#include "BCPBEKey.h"
#include "BaseWrapCipher.h"
#include "BouncyCastleProvider.h"
#include "CipherParameters.h"
#include "GOST28147WrapParameterSpec.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "InvalidCipherTextException.h"
#include "J2ObjC_source.h"
#include "JcaJceHelper.h"
#include "KeyParameter.h"
#include "PBE.h"
#include "ParametersWithIV.h"
#include "ParametersWithRandom.h"
#include "ParametersWithSBox.h"
#include "ParametersWithUKM.h"
#include "PrivateKeyInfo.h"
#include "Wrapper.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/RuntimeException.h"
#include "java/lang/System.h"
#include "java/lang/Throwable.h"
#include "java/security/AlgorithmParameters.h"
#include "java/security/InvalidAlgorithmParameterException.h"
#include "java/security/InvalidKeyException.h"
#include "java/security/InvalidParameterException.h"
#include "java/security/Key.h"
#include "java/security/KeyFactory.h"
#include "java/security/NoSuchAlgorithmException.h"
#include "java/security/NoSuchProviderException.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"
#include "java/security/SecureRandom.h"
#include "java/security/spec/AlgorithmParameterSpec.h"
#include "java/security/spec/InvalidKeySpecException.h"
#include "java/security/spec/PKCS8EncodedKeySpec.h"
#include "java/security/spec/X509EncodedKeySpec.h"
#include "javax/crypto/BadPaddingException.h"
#include "javax/crypto/Cipher.h"
#include "javax/crypto/CipherSpi.h"
#include "javax/crypto/IllegalBlockSizeException.h"
#include "javax/crypto/NoSuchPaddingException.h"
#include "javax/crypto/ShortBufferException.h"
#include "javax/crypto/spec/IvParameterSpec.h"
#include "javax/crypto/spec/PBEParameterSpec.h"
#include "javax/crypto/spec/RC2ParameterSpec.h"
#include "javax/crypto/spec/RC5ParameterSpec.h"
#include "javax/crypto/spec/SecretKeySpec.h"

@interface LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher () {
 @public
  IOSObjectArray *availableSpecs_;
  jint ivSize_;
  IOSByteArray *iv_;
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *wrapStream_;
  jboolean forWrapping_;
  id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher, availableSpecs_, IOSObjectArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher, iv_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher, wrapStream_, LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher, helper_, id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)

__attribute__((unused)) static JavaSecurityAlgorithmParameters *LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_createParametersInstanceWithNSString_(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher *self, NSString *algorithm);

@interface LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException () {
 @public
  JavaLangThrowable *cause_InvalidKeyOrParametersException_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException, cause_InvalidKeyOrParametersException_, JavaLangThrowable *)

@implementation LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleCryptoWrapper:(id<LibOrgBouncycastleCryptoWrapper>)wrapEngine {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_initWithLibOrgBouncycastleCryptoWrapper_(self, wrapEngine);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoWrapper:(id<LibOrgBouncycastleCryptoWrapper>)wrapEngine
                                                withInt:(jint)ivSize {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_initWithLibOrgBouncycastleCryptoWrapper_withInt_(self, wrapEngine, ivSize);
  return self;
}

- (jint)engineGetBlockSize {
  return 0;
}

- (IOSByteArray *)engineGetIV {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(iv_);
}

- (jint)engineGetKeySizeWithJavaSecurityKey:(id<JavaSecurityKey>)key {
  return ((IOSByteArray *) nil_chk([((id<JavaSecurityKey>) nil_chk(key)) getEncoded]))->size_ * 8;
}

- (jint)engineGetOutputSizeWithInt:(jint)inputLen {
  return -1;
}

- (JavaSecurityAlgorithmParameters *)engineGetParameters {
  if (engineParams_ == nil) {
    if (iv_ != nil) {
      NSString *name = [((id<LibOrgBouncycastleCryptoWrapper>) nil_chk(wrapEngine_)) getAlgorithmName];
      if ([((NSString *) nil_chk(name)) java_indexOf:'/'] >= 0) {
        name = [name java_substring:0 endIndex:[name java_indexOf:'/']];
      }
      @try {
        engineParams_ = LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_createParametersInstanceWithNSString_(self, name);
        [((JavaSecurityAlgorithmParameters *) nil_chk(engineParams_)) init__WithJavaSecuritySpecAlgorithmParameterSpec:new_JavaxCryptoSpecIvParameterSpec_initWithByteArray_(iv_)];
      }
      @catch (JavaLangException *e) {
        @throw new_JavaLangRuntimeException_initWithNSString_([e description]);
      }
    }
  }
  return engineParams_;
}

- (JavaSecurityAlgorithmParameters *)createParametersInstanceWithNSString:(NSString *)algorithm {
  return LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_createParametersInstanceWithNSString_(self, algorithm);
}

- (void)engineSetModeWithNSString:(NSString *)mode {
  @throw new_JavaSecurityNoSuchAlgorithmException_initWithNSString_(JreStrcat("$$", @"can't support mode ", mode));
}

- (void)engineSetPaddingWithNSString:(NSString *)padding {
  @throw new_JavaxCryptoNoSuchPaddingException_initWithNSString_(JreStrcat("$$$", @"Padding ", padding, @" unknown."));
}

- (void)engineInitWithInt:(jint)opmode
      withJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  id<LibOrgBouncycastleCryptoCipherParameters> param;
  if ([key isKindOfClass:[LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey class]]) {
    LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey *k = (LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey *) key;
    if ([params isKindOfClass:[JavaxCryptoSpecPBEParameterSpec class]]) {
      param = LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util_makePBEParametersWithLibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey_withJavaSecuritySpecAlgorithmParameterSpec_withNSString_(k, params, [((id<LibOrgBouncycastleCryptoWrapper>) nil_chk(wrapEngine_)) getAlgorithmName]);
    }
    else if ([((LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey *) nil_chk(k)) getParam] != nil) {
      param = [k getParam];
    }
    else {
      @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_(@"PBE requires PBE parameters to be set.");
    }
  }
  else {
    param = new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_([((id<JavaSecurityKey>) nil_chk(key)) getEncoded]);
  }
  if ([params isKindOfClass:[JavaxCryptoSpecIvParameterSpec class]]) {
    JavaxCryptoSpecIvParameterSpec *ivSpec = (JavaxCryptoSpecIvParameterSpec *) params;
    self->iv_ = [((JavaxCryptoSpecIvParameterSpec *) nil_chk(ivSpec)) getIV];
    param = new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(param, iv_);
  }
  if ([params isKindOfClass:[LibOrgBouncycastleJcajceSpecGOST28147WrapParameterSpec class]]) {
    LibOrgBouncycastleJcajceSpecGOST28147WrapParameterSpec *spec = (LibOrgBouncycastleJcajceSpecGOST28147WrapParameterSpec *) params;
    IOSByteArray *sBox = [((LibOrgBouncycastleJcajceSpecGOST28147WrapParameterSpec *) nil_chk(spec)) getSBox];
    if (sBox != nil) {
      param = new_LibOrgBouncycastleCryptoParamsParametersWithSBox_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(param, sBox);
    }
    param = new_LibOrgBouncycastleCryptoParamsParametersWithUKM_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(param, [spec getUKM]);
  }
  if ([param isKindOfClass:[LibOrgBouncycastleCryptoParamsKeyParameter class]] && ivSize_ != 0) {
    if (opmode == JavaxCryptoCipher_WRAP_MODE || opmode == JavaxCryptoCipher_ENCRYPT_MODE) {
      iv_ = [IOSByteArray newArrayWithLength:ivSize_];
      [((JavaSecuritySecureRandom *) nil_chk(random)) nextBytesWithByteArray:iv_];
      param = new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(param, iv_);
    }
  }
  if (random != nil) {
    param = new_LibOrgBouncycastleCryptoParamsParametersWithRandom_initWithLibOrgBouncycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(param, random);
  }
  @try {
    switch (opmode) {
      case JavaxCryptoCipher_WRAP_MODE:
      [((id<LibOrgBouncycastleCryptoWrapper>) nil_chk(wrapEngine_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:param];
      self->wrapStream_ = nil;
      self->forWrapping_ = true;
      break;
      case JavaxCryptoCipher_UNWRAP_MODE:
      [((id<LibOrgBouncycastleCryptoWrapper>) nil_chk(wrapEngine_)) init__WithBoolean:false withLibOrgBouncycastleCryptoCipherParameters:param];
      self->wrapStream_ = nil;
      self->forWrapping_ = false;
      break;
      case JavaxCryptoCipher_ENCRYPT_MODE:
      [((id<LibOrgBouncycastleCryptoWrapper>) nil_chk(wrapEngine_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:param];
      self->wrapStream_ = new_LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream_init();
      self->forWrapping_ = true;
      break;
      case JavaxCryptoCipher_DECRYPT_MODE:
      [((id<LibOrgBouncycastleCryptoWrapper>) nil_chk(wrapEngine_)) init__WithBoolean:false withLibOrgBouncycastleCryptoCipherParameters:param];
      self->wrapStream_ = new_LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream_init();
      self->forWrapping_ = false;
      break;
      default:
      @throw new_JavaSecurityInvalidParameterException_initWithNSString_(@"Unknown mode parameter passed to init.");
    }
  }
  @catch (JavaLangException *e) {
    @throw new_LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException_initWithNSString_withJavaLangThrowable_([e getMessage], e);
  }
}

- (void)engineInitWithInt:(jint)opmode
      withJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecurityAlgorithmParameters:(JavaSecurityAlgorithmParameters *)params
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  id<JavaSecuritySpecAlgorithmParameterSpec> paramSpec = nil;
  if (params != nil) {
    for (jint i = 0; i != ((IOSObjectArray *) nil_chk(availableSpecs_))->size_; i++) {
      @try {
        paramSpec = [params getParameterSpecWithIOSClass:IOSObjectArray_Get(availableSpecs_, i)];
        break;
      }
      @catch (JavaLangException *e) {
      }
    }
    if (paramSpec == nil) {
      @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_(JreStrcat("$$", @"can't handle parameter ", [params description]));
    }
  }
  engineParams_ = params;
  [self engineInitWithInt:opmode withJavaSecurityKey:key withJavaSecuritySpecAlgorithmParameterSpec:paramSpec withJavaSecuritySecureRandom:random];
}

- (void)engineInitWithInt:(jint)opmode
      withJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  @try {
    [self engineInitWithInt:opmode withJavaSecurityKey:key withJavaSecuritySpecAlgorithmParameterSpec:nil withJavaSecuritySecureRandom:random];
  }
  @catch (JavaSecurityInvalidAlgorithmParameterException *e) {
    @throw new_LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException_initWithNSString_withJavaLangThrowable_([e getMessage], e);
  }
}

- (IOSByteArray *)engineUpdateWithByteArray:(IOSByteArray *)input
                                    withInt:(jint)inputOffset
                                    withInt:(jint)inputLen {
  if (wrapStream_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"not supported in a wrapping mode");
  }
  [wrapStream_ writeWithByteArray:input withInt:inputOffset withInt:inputLen];
  return nil;
}

- (jint)engineUpdateWithByteArray:(IOSByteArray *)input
                          withInt:(jint)inputOffset
                          withInt:(jint)inputLen
                    withByteArray:(IOSByteArray *)output
                          withInt:(jint)outputOffset {
  if (wrapStream_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"not supported in a wrapping mode");
  }
  [wrapStream_ writeWithByteArray:input withInt:inputOffset withInt:inputLen];
  return 0;
}

- (IOSByteArray *)engineDoFinalWithByteArray:(IOSByteArray *)input
                                     withInt:(jint)inputOffset
                                     withInt:(jint)inputLen {
  if (wrapStream_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"not supported in a wrapping mode");
  }
  [wrapStream_ writeWithByteArray:input withInt:inputOffset withInt:inputLen];
  @try {
    if (forWrapping_) {
      @try {
        return [((id<LibOrgBouncycastleCryptoWrapper>) nil_chk(wrapEngine_)) wrapWithByteArray:[((LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *) nil_chk(wrapStream_)) getBuf] withInt:0 withInt:[((LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *) nil_chk(wrapStream_)) size]];
      }
      @catch (JavaLangException *e) {
        @throw new_JavaxCryptoIllegalBlockSizeException_initWithNSString_([e getMessage]);
      }
    }
    else {
      @try {
        return [((id<LibOrgBouncycastleCryptoWrapper>) nil_chk(wrapEngine_)) unwrapWithByteArray:[((LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *) nil_chk(wrapStream_)) getBuf] withInt:0 withInt:[((LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *) nil_chk(wrapStream_)) size]];
      }
      @catch (LibOrgBouncycastleCryptoInvalidCipherTextException *e) {
        @throw new_JavaxCryptoBadPaddingException_initWithNSString_([e getMessage]);
      }
    }
  }
  @finally {
    [((LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *) nil_chk(wrapStream_)) erase];
  }
}

- (jint)engineDoFinalWithByteArray:(IOSByteArray *)input
                           withInt:(jint)inputOffset
                           withInt:(jint)inputLen
                     withByteArray:(IOSByteArray *)output
                           withInt:(jint)outputOffset {
  if (wrapStream_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"not supported in a wrapping mode");
  }
  [wrapStream_ writeWithByteArray:input withInt:inputOffset withInt:inputLen];
  @try {
    IOSByteArray *enc;
    if (forWrapping_) {
      @try {
        enc = [((id<LibOrgBouncycastleCryptoWrapper>) nil_chk(wrapEngine_)) wrapWithByteArray:[((LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *) nil_chk(wrapStream_)) getBuf] withInt:0 withInt:[((LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *) nil_chk(wrapStream_)) size]];
      }
      @catch (JavaLangException *e) {
        @throw new_JavaxCryptoIllegalBlockSizeException_initWithNSString_([e getMessage]);
      }
    }
    else {
      @try {
        enc = [((id<LibOrgBouncycastleCryptoWrapper>) nil_chk(wrapEngine_)) unwrapWithByteArray:[((LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *) nil_chk(wrapStream_)) getBuf] withInt:0 withInt:[((LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *) nil_chk(wrapStream_)) size]];
      }
      @catch (LibOrgBouncycastleCryptoInvalidCipherTextException *e) {
        @throw new_JavaxCryptoBadPaddingException_initWithNSString_([e getMessage]);
      }
    }
    if (outputOffset + ((IOSByteArray *) nil_chk(enc))->size_ > ((IOSByteArray *) nil_chk(output))->size_) {
      @throw new_JavaxCryptoShortBufferException_initWithNSString_(@"output buffer too short for input.");
    }
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(enc, 0, output, outputOffset, enc->size_);
    return enc->size_;
  }
  @finally {
    [((LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *) nil_chk(wrapStream_)) erase];
  }
}

- (IOSByteArray *)engineWrapWithJavaSecurityKey:(id<JavaSecurityKey>)key {
  IOSByteArray *encoded = [((id<JavaSecurityKey>) nil_chk(key)) getEncoded];
  if (encoded == nil) {
    @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"Cannot wrap key, null encoding.");
  }
  @try {
    if (wrapEngine_ == nil) {
      return [self engineDoFinalWithByteArray:encoded withInt:0 withInt:encoded->size_];
    }
    else {
      return [wrapEngine_ wrapWithByteArray:encoded withInt:0 withInt:encoded->size_];
    }
  }
  @catch (JavaxCryptoBadPaddingException *e) {
    @throw new_JavaxCryptoIllegalBlockSizeException_initWithNSString_([e getMessage]);
  }
}

- (id<JavaSecurityKey>)engineUnwrapWithByteArray:(IOSByteArray *)wrappedKey
                                    withNSString:(NSString *)wrappedKeyAlgorithm
                                         withInt:(jint)wrappedKeyType {
  IOSByteArray *encoded;
  @try {
    if (wrapEngine_ == nil) {
      encoded = [self engineDoFinalWithByteArray:wrappedKey withInt:0 withInt:((IOSByteArray *) nil_chk(wrappedKey))->size_];
    }
    else {
      encoded = [wrapEngine_ unwrapWithByteArray:wrappedKey withInt:0 withInt:((IOSByteArray *) nil_chk(wrappedKey))->size_];
    }
  }
  @catch (LibOrgBouncycastleCryptoInvalidCipherTextException *e) {
    @throw new_JavaSecurityInvalidKeyException_initWithNSString_([e getMessage]);
  }
  @catch (JavaxCryptoBadPaddingException *e) {
    @throw new_JavaSecurityInvalidKeyException_initWithNSString_([e getMessage]);
  }
  @catch (JavaxCryptoIllegalBlockSizeException *e2) {
    @throw new_JavaSecurityInvalidKeyException_initWithNSString_([e2 getMessage]);
  }
  if (wrappedKeyType == JavaxCryptoCipher_SECRET_KEY) {
    return new_JavaxCryptoSpecSecretKeySpec_initWithByteArray_withNSString_(encoded, wrappedKeyAlgorithm);
  }
  else if ([((NSString *) nil_chk(wrappedKeyAlgorithm)) isEqual:@""] && wrappedKeyType == JavaxCryptoCipher_PRIVATE_KEY) {
    @try {
      LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *in = LibOrgBouncycastleAsn1PkcsPrivateKeyInfo_getInstanceWithId_(encoded);
      id<JavaSecurityPrivateKey> privKey = LibOrgBouncycastleJceProviderBouncyCastleProvider_getPrivateKeyWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(in);
      if (privKey != nil) {
        return privKey;
      }
      else {
        @throw new_JavaSecurityInvalidKeyException_initWithNSString_(JreStrcat("$@$", @"algorithm ", [((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *) nil_chk(in)) getPrivateKeyAlgorithm])) getAlgorithm], @" not supported"));
      }
    }
    @catch (JavaLangException *e) {
      @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"Invalid key encoding.");
    }
  }
  else {
    @try {
      JavaSecurityKeyFactory *kf = [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(helper_)) createKeyFactoryWithNSString:wrappedKeyAlgorithm];
      if (wrappedKeyType == JavaxCryptoCipher_PUBLIC_KEY) {
        return [((JavaSecurityKeyFactory *) nil_chk(kf)) generatePublicWithJavaSecuritySpecKeySpec:new_JavaSecuritySpecX509EncodedKeySpec_initWithByteArray_(encoded)];
      }
      else if (wrappedKeyType == JavaxCryptoCipher_PRIVATE_KEY) {
        return [((JavaSecurityKeyFactory *) nil_chk(kf)) generatePrivateWithJavaSecuritySpecKeySpec:new_JavaSecuritySpecPKCS8EncodedKeySpec_initWithByteArray_(encoded)];
      }
    }
    @catch (JavaSecurityNoSuchProviderException *e) {
      @throw new_JavaSecurityInvalidKeyException_initWithNSString_(JreStrcat("$$", @"Unknown key type ", [e getMessage]));
    }
    @catch (JavaSecuritySpecInvalidKeySpecException *e2) {
      @throw new_JavaSecurityInvalidKeyException_initWithNSString_(JreStrcat("$$", @"Unknown key type ", [e2 getMessage]));
    }
    @throw new_JavaSecurityInvalidKeyException_initWithNSString_(JreStrcat("$I", @"Unknown key type ", wrappedKeyType));
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x4, 2, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x4, 4, 5, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityAlgorithmParameters;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityAlgorithmParameters;", 0x14, 6, 7, 8, -1, -1, -1 },
    { NULL, "V", 0x4, 9, 7, 10, -1, -1, -1 },
    { NULL, "V", 0x4, 11, 7, 12, -1, -1, -1 },
    { NULL, "V", 0x4, 13, 14, 15, -1, -1, -1 },
    { NULL, "V", 0x4, 13, 16, 15, -1, -1, -1 },
    { NULL, "V", 0x4, 13, 17, 18, -1, -1, -1 },
    { NULL, "[B", 0x4, 19, 20, -1, -1, -1, -1 },
    { NULL, "I", 0x4, 19, 21, 22, -1, -1, -1 },
    { NULL, "[B", 0x4, 23, 20, 24, -1, -1, -1 },
    { NULL, "I", 0x4, 23, 21, 25, -1, -1, -1 },
    { NULL, "[B", 0x4, 26, 3, 27, -1, -1, -1 },
    { NULL, "LJavaSecurityKey;", 0x4, 28, 29, 30, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoWrapper:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleCryptoWrapper:withInt:);
  methods[3].selector = @selector(engineGetBlockSize);
  methods[4].selector = @selector(engineGetIV);
  methods[5].selector = @selector(engineGetKeySizeWithJavaSecurityKey:);
  methods[6].selector = @selector(engineGetOutputSizeWithInt:);
  methods[7].selector = @selector(engineGetParameters);
  methods[8].selector = @selector(createParametersInstanceWithNSString:);
  methods[9].selector = @selector(engineSetModeWithNSString:);
  methods[10].selector = @selector(engineSetPaddingWithNSString:);
  methods[11].selector = @selector(engineInitWithInt:withJavaSecurityKey:withJavaSecuritySpecAlgorithmParameterSpec:withJavaSecuritySecureRandom:);
  methods[12].selector = @selector(engineInitWithInt:withJavaSecurityKey:withJavaSecurityAlgorithmParameters:withJavaSecuritySecureRandom:);
  methods[13].selector = @selector(engineInitWithInt:withJavaSecurityKey:withJavaSecuritySecureRandom:);
  methods[14].selector = @selector(engineUpdateWithByteArray:withInt:withInt:);
  methods[15].selector = @selector(engineUpdateWithByteArray:withInt:withInt:withByteArray:withInt:);
  methods[16].selector = @selector(engineDoFinalWithByteArray:withInt:withInt:);
  methods[17].selector = @selector(engineDoFinalWithByteArray:withInt:withInt:withByteArray:withInt:);
  methods[18].selector = @selector(engineWrapWithJavaSecurityKey:);
  methods[19].selector = @selector(engineUnwrapWithByteArray:withNSString:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "availableSpecs_", "[LIOSClass;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "pbeType_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "pbeHash_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "pbeKeySize_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "pbeIvSize_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "engineParams_", "LJavaSecurityAlgorithmParameters;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "wrapEngine_", "LLibOrgBouncycastleCryptoWrapper;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "ivSize_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "iv_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "wrapStream_", "LLibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forWrapping_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "helper_", "LLibOrgBouncycastleJcajceUtilJcaJceHelper;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoWrapper;", "LLibOrgBouncycastleCryptoWrapper;I", "engineGetKeySize", "LJavaSecurityKey;", "engineGetOutputSize", "I", "createParametersInstance", "LNSString;", "LJavaSecurityNoSuchAlgorithmException;LJavaSecurityNoSuchProviderException;", "engineSetMode", "LJavaSecurityNoSuchAlgorithmException;", "engineSetPadding", "LJavaxCryptoNoSuchPaddingException;", "engineInit", "ILJavaSecurityKey;LJavaSecuritySpecAlgorithmParameterSpec;LJavaSecuritySecureRandom;", "LJavaSecurityInvalidKeyException;LJavaSecurityInvalidAlgorithmParameterException;", "ILJavaSecurityKey;LJavaSecurityAlgorithmParameters;LJavaSecuritySecureRandom;", "ILJavaSecurityKey;LJavaSecuritySecureRandom;", "LJavaSecurityInvalidKeyException;", "engineUpdate", "[BII", "[BII[BI", "LJavaxCryptoShortBufferException;", "engineDoFinal", "LJavaxCryptoIllegalBlockSizeException;LJavaxCryptoBadPaddingException;", "LJavaxCryptoIllegalBlockSizeException;LJavaxCryptoBadPaddingException;LJavaxCryptoShortBufferException;", "engineWrap", "LJavaxCryptoIllegalBlockSizeException;LJavaSecurityInvalidKeyException;", "engineUnwrap", "[BLNSString;I", "LJavaSecurityInvalidKeyException;LJavaSecurityNoSuchAlgorithmException;", "LLibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream;LLibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher = { "BaseWrapCipher", "lib.org.bouncycastle.jcajce.provider.symmetric.util", ptrTable, methods, fields, 7, 0x401, 20, 12, -1, 31, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_init(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher *self) {
  JavaxCryptoCipherSpi_init(self);
  self->availableSpecs_ = [IOSObjectArray newArrayWithObjects:(id[]){ LibOrgBouncycastleJcajceSpecGOST28147WrapParameterSpec_class_(), JavaxCryptoSpecPBEParameterSpec_class_(), JavaxCryptoSpecRC2ParameterSpec_class_(), JavaxCryptoSpecRC5ParameterSpec_class_(), JavaxCryptoSpecIvParameterSpec_class_() } count:5 type:IOSClass_class_()];
  self->pbeType_ = LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_PKCS12;
  self->pbeHash_ = LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA1;
  self->engineParams_ = nil;
  self->wrapEngine_ = nil;
  self->wrapStream_ = nil;
  self->helper_ = new_LibOrgBouncycastleJcajceUtilBCJcaJceHelper_init();
}

void LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_initWithLibOrgBouncycastleCryptoWrapper_(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher *self, id<LibOrgBouncycastleCryptoWrapper> wrapEngine) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_initWithLibOrgBouncycastleCryptoWrapper_withInt_(self, wrapEngine, 0);
}

void LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_initWithLibOrgBouncycastleCryptoWrapper_withInt_(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher *self, id<LibOrgBouncycastleCryptoWrapper> wrapEngine, jint ivSize) {
  JavaxCryptoCipherSpi_init(self);
  self->availableSpecs_ = [IOSObjectArray newArrayWithObjects:(id[]){ LibOrgBouncycastleJcajceSpecGOST28147WrapParameterSpec_class_(), JavaxCryptoSpecPBEParameterSpec_class_(), JavaxCryptoSpecRC2ParameterSpec_class_(), JavaxCryptoSpecRC5ParameterSpec_class_(), JavaxCryptoSpecIvParameterSpec_class_() } count:5 type:IOSClass_class_()];
  self->pbeType_ = LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_PKCS12;
  self->pbeHash_ = LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA1;
  self->engineParams_ = nil;
  self->wrapEngine_ = nil;
  self->wrapStream_ = nil;
  self->helper_ = new_LibOrgBouncycastleJcajceUtilBCJcaJceHelper_init();
  self->wrapEngine_ = wrapEngine;
  self->ivSize_ = ivSize;
}

JavaSecurityAlgorithmParameters *LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_createParametersInstanceWithNSString_(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher *self, NSString *algorithm) {
  return [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(self->helper_)) createAlgorithmParametersWithNSString:algorithm];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher)

@implementation LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)getBuf {
  return buf_;
}

- (void)erase {
  LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(self->buf_, (jbyte) 0);
  [self reset];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getBuf);
  methods[2].selector = @selector(erase);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream = { "ErasableOutputStream", "lib.org.bouncycastle.jcajce.provider.symmetric.util", ptrTable, methods, NULL, 7, 0x1c, 3, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream_init(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *self) {
  JavaIoByteArrayOutputStream_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *new_LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream, init)
}

LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream *create_LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_ErasableOutputStream)

@implementation LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException

- (instancetype)initWithNSString:(NSString *)msg
           withJavaLangThrowable:(JavaLangThrowable *)cause {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException_initWithNSString_withJavaLangThrowable_(self, msg, cause);
  return self;
}

- (JavaLangThrowable *)getCause {
  return cause_InvalidKeyOrParametersException_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaLangThrowable;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withJavaLangThrowable:);
  methods[1].selector = @selector(getCause);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cause_InvalidKeyOrParametersException_", "LJavaLangThrowable;", .constantValue.asLong = 0, 0x12, 1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;LJavaLangThrowable;", "cause", "LLibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException = { "InvalidKeyOrParametersException", "lib.org.bouncycastle.jcajce.provider.symmetric.util", ptrTable, methods, fields, 7, 0xc, 2, 1, 2, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException_initWithNSString_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException *self, NSString *msg, JavaLangThrowable *cause) {
  JavaSecurityInvalidKeyException_initWithNSString_(self, msg);
  self->cause_InvalidKeyOrParametersException_ = cause;
}

LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException *new_LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException_initWithNSString_withJavaLangThrowable_(NSString *msg, JavaLangThrowable *cause) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException, initWithNSString_withJavaLangThrowable_, msg, cause)
}

LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException *create_LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException_initWithNSString_withJavaLangThrowable_(NSString *msg, JavaLangThrowable *cause) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException, initWithNSString_withJavaLangThrowable_, msg, cause)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher_InvalidKeyOrParametersException)