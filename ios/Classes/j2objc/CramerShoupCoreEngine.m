//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/CramerShoupCoreEngine.java
//

#include "BigIntegers.h"
#include "CipherParameters.h"
#include "CramerShoupCiphertext.h"
#include "CramerShoupCoreEngine.h"
#include "CramerShoupKeyParameters.h"
#include "CramerShoupParameters.h"
#include "CramerShoupPrivateKeyParameters.h"
#include "CramerShoupPublicKeyParameters.h"
#include "CryptoServicesRegistrar.h"
#include "DataLengthException.h"
#include "Digest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ParametersWithRandom.h"
#include "Strings.h"
#include "java/lang/Exception.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine () {
 @public
  LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters *key_;
  JavaSecuritySecureRandom *random_;
  jboolean forEncryption_;
  IOSByteArray *label_;
}

- (JavaMathBigInteger *)generateRandomElementWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                       withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (jboolean)isValidMessageWithJavaMathBigInteger:(JavaMathBigInteger *)m
                          withJavaMathBigInteger:(JavaMathBigInteger *)p;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine, key_, LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine, random_, JavaSecuritySecureRandom *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine, label_, IOSByteArray *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_get_ONE(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_ONE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine, ONE, JavaMathBigInteger *)

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_generateRandomElementWithJavaMathBigInteger_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine *self, JavaMathBigInteger *p, JavaSecuritySecureRandom *random);

__attribute__((unused)) static jboolean LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_isValidMessageWithJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine *self, JavaMathBigInteger *m, JavaMathBigInteger *p);

inline jlong LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException_get_serialVersionUID(void);
#define LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException_serialVersionUID -6360977166495345076LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException, serialVersionUID, jlong)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine)

@implementation LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param
             withNSString:(NSString *)label {
  [self init__WithBoolean:forEncryption withLibOrgBouncycastleCryptoCipherParameters:param];
  self->label_ = LibOrgBouncycastleUtilStrings_toUTF8ByteArrayWithNSString_(label);
}

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param {
  JavaSecuritySecureRandom *providedRandom = nil;
  if ([param isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithRandom class]]) {
    LibOrgBouncycastleCryptoParamsParametersWithRandom *rParam = (LibOrgBouncycastleCryptoParamsParametersWithRandom *) param;
    key_ = (LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters *) cast_chk([((LibOrgBouncycastleCryptoParamsParametersWithRandom *) nil_chk(rParam)) getParameters], [LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters class]);
    providedRandom = [rParam getRandom];
  }
  else {
    key_ = (LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters class]);
  }
  self->random_ = [self initSecureRandomWithBoolean:forEncryption withJavaSecuritySecureRandom:providedRandom];
  self->forEncryption_ = forEncryption;
}

- (jint)getInputBlockSize {
  jint bitSize = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsCramerShoupParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters *) nil_chk(key_)) getParameters])) getP])) bitLength];
  if (forEncryption_) {
    return (bitSize + 7) / 8 - 1;
  }
  else {
    return (bitSize + 7) / 8;
  }
}

- (jint)getOutputBlockSize {
  jint bitSize = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsCramerShoupParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters *) nil_chk(key_)) getParameters])) getP])) bitLength];
  if (forEncryption_) {
    return (bitSize + 7) / 8;
  }
  else {
    return (bitSize + 7) / 8 - 1;
  }
}

- (JavaMathBigInteger *)convertInputWithByteArray:(IOSByteArray *)inArg
                                          withInt:(jint)inOff
                                          withInt:(jint)inLen {
  if (inLen > ([self getInputBlockSize] + 1)) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"input too large for Cramer Shoup cipher.");
  }
  else if (inLen == ([self getInputBlockSize] + 1) && forEncryption_) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"input too large for Cramer Shoup cipher.");
  }
  IOSByteArray *block;
  if (inOff != 0 || inLen != ((IOSByteArray *) nil_chk(inArg))->size_) {
    block = [IOSByteArray newArrayWithLength:inLen];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, block, 0, inLen);
  }
  else {
    block = inArg;
  }
  JavaMathBigInteger *res = new_JavaMathBigInteger_initWithInt_withByteArray_(1, block);
  if ([res compareToWithId:[((LibOrgBouncycastleCryptoParamsCramerShoupParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters *) nil_chk(key_)) getParameters])) getP]] >= 0) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"input too large for Cramer Shoup cipher.");
  }
  return res;
}

- (IOSByteArray *)convertOutputWithJavaMathBigInteger:(JavaMathBigInteger *)result {
  IOSByteArray *output = [((JavaMathBigInteger *) nil_chk(result)) toByteArray];
  if (!forEncryption_) {
    if (IOSByteArray_Get(nil_chk(output), 0) == 0 && output->size_ > [self getOutputBlockSize]) {
      IOSByteArray *tmp = [IOSByteArray newArrayWithLength:output->size_ - 1];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(output, 1, tmp, 0, tmp->size_);
      return tmp;
    }
    if (output->size_ < [self getOutputBlockSize]) {
      IOSByteArray *tmp = [IOSByteArray newArrayWithLength:[self getOutputBlockSize]];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(output, 0, tmp, tmp->size_ - output->size_, output->size_);
      return tmp;
    }
  }
  else {
    if (IOSByteArray_Get(nil_chk(output), 0) == 0) {
      IOSByteArray *tmp = [IOSByteArray newArrayWithLength:output->size_ - 1];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(output, 1, tmp, 0, tmp->size_);
      return tmp;
    }
  }
  return output;
}

- (LibOrgBouncycastleCryptoEnginesCramerShoupCiphertext *)encryptBlockWithJavaMathBigInteger:(JavaMathBigInteger *)input {
  LibOrgBouncycastleCryptoEnginesCramerShoupCiphertext *result = nil;
  if (![((LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters *) nil_chk(key_)) isPrivate] && self->forEncryption_ && [key_ isKindOfClass:[LibOrgBouncycastleCryptoParamsCramerShoupPublicKeyParameters class]]) {
    LibOrgBouncycastleCryptoParamsCramerShoupPublicKeyParameters *pk = (LibOrgBouncycastleCryptoParamsCramerShoupPublicKeyParameters *) cast_chk(key_, [LibOrgBouncycastleCryptoParamsCramerShoupPublicKeyParameters class]);
    JavaMathBigInteger *p = [((LibOrgBouncycastleCryptoParamsCramerShoupParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsCramerShoupPublicKeyParameters *) nil_chk(pk)) getParameters])) getP];
    JavaMathBigInteger *g1 = [((LibOrgBouncycastleCryptoParamsCramerShoupParameters *) nil_chk([pk getParameters])) getG1];
    JavaMathBigInteger *g2 = [((LibOrgBouncycastleCryptoParamsCramerShoupParameters *) nil_chk([pk getParameters])) getG2];
    JavaMathBigInteger *h = [pk getH];
    if (!LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_isValidMessageWithJavaMathBigInteger_withJavaMathBigInteger_(self, input, p)) {
      return result;
    }
    JavaMathBigInteger *r = LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_generateRandomElementWithJavaMathBigInteger_withJavaSecuritySecureRandom_(self, p, random_);
    JavaMathBigInteger *u1;
    JavaMathBigInteger *u2;
    JavaMathBigInteger *v;
    JavaMathBigInteger *e;
    JavaMathBigInteger *a;
    u1 = [((JavaMathBigInteger *) nil_chk(g1)) modPowWithJavaMathBigInteger:r withJavaMathBigInteger:p];
    u2 = [((JavaMathBigInteger *) nil_chk(g2)) modPowWithJavaMathBigInteger:r withJavaMathBigInteger:p];
    e = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(h)) modPowWithJavaMathBigInteger:r withJavaMathBigInteger:p])) multiplyWithJavaMathBigInteger:input])) modWithJavaMathBigInteger:p];
    id<LibOrgBouncycastleCryptoDigest> digest = [((LibOrgBouncycastleCryptoParamsCramerShoupParameters *) nil_chk([pk getParameters])) getH];
    IOSByteArray *u1Bytes = [((JavaMathBigInteger *) nil_chk(u1)) toByteArray];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest)) updateWithByteArray:u1Bytes withInt:0 withInt:((IOSByteArray *) nil_chk(u1Bytes))->size_];
    IOSByteArray *u2Bytes = [((JavaMathBigInteger *) nil_chk(u2)) toByteArray];
    [digest updateWithByteArray:u2Bytes withInt:0 withInt:((IOSByteArray *) nil_chk(u2Bytes))->size_];
    IOSByteArray *eBytes = [((JavaMathBigInteger *) nil_chk(e)) toByteArray];
    [digest updateWithByteArray:eBytes withInt:0 withInt:((IOSByteArray *) nil_chk(eBytes))->size_];
    if (self->label_ != nil) {
      IOSByteArray *lBytes = self->label_;
      [digest updateWithByteArray:lBytes withInt:0 withInt:lBytes->size_];
    }
    IOSByteArray *out = [IOSByteArray newArrayWithLength:[digest getDigestSize]];
    [digest doFinalWithByteArray:out withInt:0];
    a = new_JavaMathBigInteger_initWithInt_withByteArray_(1, out);
    v = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk([pk getC])) modPowWithJavaMathBigInteger:r withJavaMathBigInteger:p])) multiplyWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk([pk getD])) modPowWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(r)) multiplyWithJavaMathBigInteger:a] withJavaMathBigInteger:p]])) modWithJavaMathBigInteger:p];
    result = new_LibOrgBouncycastleCryptoEnginesCramerShoupCiphertext_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(u1, u2, e, v);
  }
  return result;
}

- (JavaMathBigInteger *)decryptBlockWithLibOrgBouncycastleCryptoEnginesCramerShoupCiphertext:(LibOrgBouncycastleCryptoEnginesCramerShoupCiphertext *)input {
  JavaMathBigInteger *result = nil;
  if ([((LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters *) nil_chk(key_)) isPrivate] && !self->forEncryption_ && [key_ isKindOfClass:[LibOrgBouncycastleCryptoParamsCramerShoupPrivateKeyParameters class]]) {
    LibOrgBouncycastleCryptoParamsCramerShoupPrivateKeyParameters *sk = (LibOrgBouncycastleCryptoParamsCramerShoupPrivateKeyParameters *) cast_chk(key_, [LibOrgBouncycastleCryptoParamsCramerShoupPrivateKeyParameters class]);
    JavaMathBigInteger *p = [((LibOrgBouncycastleCryptoParamsCramerShoupParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsCramerShoupPrivateKeyParameters *) nil_chk(sk)) getParameters])) getP];
    id<LibOrgBouncycastleCryptoDigest> digest = [((LibOrgBouncycastleCryptoParamsCramerShoupParameters *) nil_chk([sk getParameters])) getH];
    IOSByteArray *u1Bytes = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoEnginesCramerShoupCiphertext *) nil_chk(input)) getU1])) toByteArray];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest)) updateWithByteArray:u1Bytes withInt:0 withInt:((IOSByteArray *) nil_chk(u1Bytes))->size_];
    IOSByteArray *u2Bytes = [((JavaMathBigInteger *) nil_chk([input getU2])) toByteArray];
    [digest updateWithByteArray:u2Bytes withInt:0 withInt:((IOSByteArray *) nil_chk(u2Bytes))->size_];
    IOSByteArray *eBytes = [((JavaMathBigInteger *) nil_chk([input getE])) toByteArray];
    [digest updateWithByteArray:eBytes withInt:0 withInt:((IOSByteArray *) nil_chk(eBytes))->size_];
    if (self->label_ != nil) {
      IOSByteArray *lBytes = self->label_;
      [digest updateWithByteArray:lBytes withInt:0 withInt:lBytes->size_];
    }
    IOSByteArray *out = [IOSByteArray newArrayWithLength:[digest getDigestSize]];
    [digest doFinalWithByteArray:out withInt:0];
    JavaMathBigInteger *a = new_JavaMathBigInteger_initWithInt_withByteArray_(1, out);
    JavaMathBigInteger *v = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(input->u1_)) modPowWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk([sk getX1])) addWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk([sk getY1])) multiplyWithJavaMathBigInteger:a]] withJavaMathBigInteger:p])) multiplyWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(input->u2_)) modPowWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk([sk getX2])) addWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk([sk getY2])) multiplyWithJavaMathBigInteger:a]] withJavaMathBigInteger:p]])) modWithJavaMathBigInteger:p];
    if ([((JavaMathBigInteger *) nil_chk(input->v_)) isEqual:v]) {
      result = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(input->e_)) multiplyWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(input->u1_)) modPowWithJavaMathBigInteger:[sk getZ] withJavaMathBigInteger:p])) modInverseWithJavaMathBigInteger:p]])) modWithJavaMathBigInteger:p];
    }
    else {
      @throw new_LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException_initWithNSString_(@"Sorry, that ciphertext is not correct");
    }
  }
  return result;
}

- (JavaMathBigInteger *)generateRandomElementWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                       withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_generateRandomElementWithJavaMathBigInteger_withJavaSecuritySecureRandom_(self, p, random);
}

- (jboolean)isValidMessageWithJavaMathBigInteger:(JavaMathBigInteger *)m
                          withJavaMathBigInteger:(JavaMathBigInteger *)p {
  return LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_isValidMessageWithJavaMathBigInteger_withJavaMathBigInteger_(self, m, p);
}

- (JavaSecuritySecureRandom *)initSecureRandomWithBoolean:(jboolean)needed
                             withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)provided {
  return !needed ? nil : (provided != nil) ? provided : LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom();
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoEnginesCramerShoupCiphertext;", 0x1, 7, 6, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, 8, 9, 10, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x2, 11, 12, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 13, 14, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySecureRandom;", 0x4, 15, 16, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:withNSString:);
  methods[2].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[3].selector = @selector(getInputBlockSize);
  methods[4].selector = @selector(getOutputBlockSize);
  methods[5].selector = @selector(convertInputWithByteArray:withInt:withInt:);
  methods[6].selector = @selector(convertOutputWithJavaMathBigInteger:);
  methods[7].selector = @selector(encryptBlockWithJavaMathBigInteger:);
  methods[8].selector = @selector(decryptBlockWithLibOrgBouncycastleCryptoEnginesCramerShoupCiphertext:);
  methods[9].selector = @selector(generateRandomElementWithJavaMathBigInteger:withJavaSecuritySecureRandom:);
  methods[10].selector = @selector(isValidMessageWithJavaMathBigInteger:withJavaMathBigInteger:);
  methods[11].selector = @selector(initSecureRandomWithBoolean:withJavaSecuritySecureRandom:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 17, -1, -1 },
    { "key_", "LLibOrgBouncycastleCryptoParamsCramerShoupKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forEncryption_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "label_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLLibOrgBouncycastleCryptoCipherParameters;LNSString;", "ZLLibOrgBouncycastleCryptoCipherParameters;", "convertInput", "[BII", "convertOutput", "LJavaMathBigInteger;", "encryptBlock", "decryptBlock", "LLibOrgBouncycastleCryptoEnginesCramerShoupCiphertext;", "LLibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException;", "generateRandomElement", "LJavaMathBigInteger;LJavaSecuritySecureRandom;", "isValidMessage", "LJavaMathBigInteger;LJavaMathBigInteger;", "initSecureRandom", "ZLJavaSecuritySecureRandom;", &LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_ONE };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine = { "CramerShoupCoreEngine", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 12, 5, -1, 10, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine class]) {
    LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine)
  }
}

@end

void LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_init(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine *self) {
  NSObject_init(self);
  self->label_ = nil;
}

LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine *new_LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine, init)
}

LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine *create_LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine, init)
}

JavaMathBigInteger *LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_generateRandomElementWithJavaMathBigInteger_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine *self, JavaMathBigInteger *p, JavaSecuritySecureRandom *random) {
  return LibOrgBouncycastleUtilBigIntegers_createRandomInRangeWithJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_ONE, [((JavaMathBigInteger *) nil_chk(p)) subtractWithJavaMathBigInteger:LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_ONE], random);
}

jboolean LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_isValidMessageWithJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine *self, JavaMathBigInteger *m, JavaMathBigInteger *p) {
  return [((JavaMathBigInteger *) nil_chk(m)) compareToWithId:p] < 0;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine)

@implementation LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException

- (instancetype)initWithNSString:(NSString *)msg {
  LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException_initWithNSString_(self, msg);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serialVersionUID", "J", .constantValue.asLong = LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException_serialVersionUID, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "LLibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException = { "CramerShoupCiphertextException", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, fields, 7, 0x9, 1, 1, 1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException;
}

@end

void LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException_initWithNSString_(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException *self, NSString *msg) {
  JavaLangException_initWithNSString_(self, msg);
}

LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException *new_LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException_initWithNSString_(NSString *msg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException, initWithNSString_, msg)
}

LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException *create_LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException_initWithNSString_(NSString *msg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException, initWithNSString_, msg)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException)
