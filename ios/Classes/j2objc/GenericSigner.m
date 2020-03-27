//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/GenericSigner.java
//

#include "Arrays.h"
#include "AsymmetricBlockCipher.h"
#include "AsymmetricKeyParameter.h"
#include "CipherParameters.h"
#include "Digest.h"
#include "GenericSigner.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ParametersWithRandom.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoSignersGenericSigner () {
 @public
  id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> engine_;
  id<LibOrgBouncycastleCryptoDigest> digest_;
  jboolean forSigning_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersGenericSigner, engine_, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersGenericSigner, digest_, id<LibOrgBouncycastleCryptoDigest>)

@implementation LibOrgBouncycastleCryptoSignersGenericSigner

- (instancetype)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)engine
                                   withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest {
  LibOrgBouncycastleCryptoSignersGenericSigner_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(self, engine, digest);
  return self;
}

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters {
  self->forSigning_ = forSigning;
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *k;
  if ([parameters isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithRandom class]]) {
    k = (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *) cast_chk([((LibOrgBouncycastleCryptoParamsParametersWithRandom *) nil_chk(((LibOrgBouncycastleCryptoParamsParametersWithRandom *) parameters))) getParameters], [LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter class]);
  }
  else {
    k = (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *) cast_chk(parameters, [LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter class]);
  }
  if (forSigning && ![((LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *) nil_chk(k)) isPrivate]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"signing requires private key");
  }
  if (!forSigning && [((LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *) nil_chk(k)) isPrivate]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"verification requires public key");
  }
  [self reset];
  [((id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>) nil_chk(engine_)) init__WithBoolean:forSigning withLibOrgBouncycastleCryptoCipherParameters:parameters];
}

- (void)updateWithByte:(jbyte)input {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByte:input];
}

- (void)updateWithByteArray:(IOSByteArray *)input
                    withInt:(jint)inOff
                    withInt:(jint)length {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:input withInt:inOff withInt:length];
}

- (IOSByteArray *)generateSignature {
  if (!forSigning_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"GenericSigner not initialised for signature generation.");
  }
  IOSByteArray *hash_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize]];
  [digest_ doFinalWithByteArray:hash_ withInt:0];
  return [((id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>) nil_chk(engine_)) processBlockWithByteArray:hash_ withInt:0 withInt:hash_->size_];
}

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)signature {
  if (forSigning_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"GenericSigner not initialised for verification");
  }
  IOSByteArray *hash_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize]];
  [digest_ doFinalWithByteArray:hash_ withInt:0];
  @try {
    IOSByteArray *sig = [((id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>) nil_chk(engine_)) processBlockWithByteArray:signature withInt:0 withInt:((IOSByteArray *) nil_chk(signature))->size_];
    if (((IOSByteArray *) nil_chk(sig))->size_ < hash_->size_) {
      IOSByteArray *tmp = [IOSByteArray newArrayWithLength:hash_->size_];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(sig, 0, tmp, tmp->size_ - sig->size_, sig->size_);
      sig = tmp;
    }
    return LibOrgBouncycastleUtilArrays_constantTimeAreEqualWithByteArray_withByteArray_(sig, hash_);
  }
  @catch (JavaLangException *e) {
    return false;
  }
}

- (void)reset {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) reset];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 5, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 6, -1, -1, -1 },
    { NULL, "Z", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:withLibOrgBouncycastleCryptoDigest:);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(updateWithByte:);
  methods[3].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[4].selector = @selector(generateSignature);
  methods[5].selector = @selector(verifySignatureWithByteArray:);
  methods[6].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "engine_", "LLibOrgBouncycastleCryptoAsymmetricBlockCipher;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "digest_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "forSigning_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoAsymmetricBlockCipher;LLibOrgBouncycastleCryptoDigest;", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "update", "B", "[BII", "LLibOrgBouncycastleCryptoCryptoException;LLibOrgBouncycastleCryptoDataLengthException;", "verifySignature", "[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoSignersGenericSigner = { "GenericSigner", "lib.org.bouncycastle.crypto.signers", ptrTable, methods, fields, 7, 0x1, 7, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoSignersGenericSigner;
}

@end

void LibOrgBouncycastleCryptoSignersGenericSigner_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoSignersGenericSigner *self, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> engine, id<LibOrgBouncycastleCryptoDigest> digest) {
  NSObject_init(self);
  self->engine_ = engine;
  self->digest_ = digest;
}

LibOrgBouncycastleCryptoSignersGenericSigner *new_LibOrgBouncycastleCryptoSignersGenericSigner_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> engine, id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoSignersGenericSigner, initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_, engine, digest)
}

LibOrgBouncycastleCryptoSignersGenericSigner *create_LibOrgBouncycastleCryptoSignersGenericSigner_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> engine, id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoSignersGenericSigner, initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_, engine, digest)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoSignersGenericSigner)
