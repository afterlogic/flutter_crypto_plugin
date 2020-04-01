//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/CFBBlockCipher.java
//

#include "Arrays.h"
#include "BlockCipher.h"
#include "CFBBlockCipher.h"
#include "CipherParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ParametersWithIV.h"
#include "StreamBlockCipher.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoModesCFBBlockCipher () {
 @public
  IOSByteArray *IV_;
  IOSByteArray *cfbV_;
  IOSByteArray *cfbOutV_;
  IOSByteArray *inBuf_;
  jint blockSize_;
  id<LibOrgBouncycastleCryptoBlockCipher> cipher_CFBBlockCipher_;
  jboolean encrypting_;
  jint byteCount_;
}

- (jbyte)encryptByteWithByte:(jbyte)inArg;

- (jbyte)decryptByteWithByte:(jbyte)inArg;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesCFBBlockCipher, IV_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesCFBBlockCipher, cfbV_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesCFBBlockCipher, cfbOutV_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesCFBBlockCipher, inBuf_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesCFBBlockCipher, cipher_CFBBlockCipher_, id<LibOrgBouncycastleCryptoBlockCipher>)

__attribute__((unused)) static jbyte LibOrgBouncycastleCryptoModesCFBBlockCipher_encryptByteWithByte_(LibOrgBouncycastleCryptoModesCFBBlockCipher *self, jbyte inArg);

__attribute__((unused)) static jbyte LibOrgBouncycastleCryptoModesCFBBlockCipher_decryptByteWithByte_(LibOrgBouncycastleCryptoModesCFBBlockCipher *self, jbyte inArg);

@implementation LibOrgBouncycastleCryptoModesCFBBlockCipher

- (instancetype)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)cipher
                                                    withInt:(jint)bitBlockSize {
  LibOrgBouncycastleCryptoModesCFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_(self, cipher, bitBlockSize);
  return self;
}

- (void)init__WithBoolean:(jboolean)encrypting
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  self->encrypting_ = encrypting;
  if ([params isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithIV class]]) {
    LibOrgBouncycastleCryptoParamsParametersWithIV *ivParam = (LibOrgBouncycastleCryptoParamsParametersWithIV *) params;
    IOSByteArray *iv = [((LibOrgBouncycastleCryptoParamsParametersWithIV *) nil_chk(ivParam)) getIV];
    if (((IOSByteArray *) nil_chk(iv))->size_ < ((IOSByteArray *) nil_chk(IV_))->size_) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(iv, 0, IV_, IV_->size_ - iv->size_, iv->size_);
      for (jint i = 0; i < ((IOSByteArray *) nil_chk(IV_))->size_ - iv->size_; i++) {
        *IOSByteArray_GetRef(IV_, i) = 0;
      }
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(iv, 0, IV_, 0, IV_->size_);
    }
    [self reset];
    if ([ivParam getParameters] != nil) {
      [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher_CFBBlockCipher_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:[ivParam getParameters]];
    }
  }
  else {
    [self reset];
    if (params != nil) {
      [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher_CFBBlockCipher_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:params];
    }
  }
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$$I", [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher_CFBBlockCipher_)) getAlgorithmName], @"/CFB", (blockSize_ * 8));
}

- (jbyte)calculateByteWithByte:(jbyte)inArg {
  return (encrypting_) ? LibOrgBouncycastleCryptoModesCFBBlockCipher_encryptByteWithByte_(self, inArg) : LibOrgBouncycastleCryptoModesCFBBlockCipher_decryptByteWithByte_(self, inArg);
}

- (jbyte)encryptByteWithByte:(jbyte)inArg {
  return LibOrgBouncycastleCryptoModesCFBBlockCipher_encryptByteWithByte_(self, inArg);
}

- (jbyte)decryptByteWithByte:(jbyte)inArg {
  return LibOrgBouncycastleCryptoModesCFBBlockCipher_decryptByteWithByte_(self, inArg);
}

- (jint)getBlockSize {
  return blockSize_;
}

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  [self processBytesWithByteArray:inArg withInt:inOff withInt:blockSize_ withByteArray:outArg withInt:outOff];
  return blockSize_;
}

- (jint)encryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  [self processBytesWithByteArray:inArg withInt:inOff withInt:blockSize_ withByteArray:outArg withInt:outOff];
  return blockSize_;
}

- (jint)decryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  [self processBytesWithByteArray:inArg withInt:inOff withInt:blockSize_ withByteArray:outArg withInt:outOff];
  return blockSize_;
}

- (IOSByteArray *)getCurrentIV {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(cfbV_);
}

- (void)reset {
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(IV_, 0, cfbV_, 0, ((IOSByteArray *) nil_chk(IV_))->size_);
  LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(inBuf_, (jbyte) 0);
  byteCount_ = 0;
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher_CFBBlockCipher_)) reset];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "B", 0x4, 4, 5, 6, -1, -1, -1 },
    { NULL, "B", 0x2, 7, 5, -1, -1, -1, -1 },
    { NULL, "B", 0x2, 8, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 9, 10, 6, -1, -1, -1 },
    { NULL, "I", 0x1, 11, 10, 6, -1, -1, -1 },
    { NULL, "I", 0x1, 12, 10, 6, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoBlockCipher:withInt:);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(calculateByteWithByte:);
  methods[4].selector = @selector(encryptByteWithByte:);
  methods[5].selector = @selector(decryptByteWithByte:);
  methods[6].selector = @selector(getBlockSize);
  methods[7].selector = @selector(processBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[8].selector = @selector(encryptBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[9].selector = @selector(decryptBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[10].selector = @selector(getCurrentIV);
  methods[11].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "IV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cfbV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cfbOutV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "inBuf_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "blockSize_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cipher_CFBBlockCipher_", "LLibOrgBouncycastleCryptoBlockCipher;", .constantValue.asLong = 0, 0x2, 13, -1, -1, -1 },
    { "encrypting_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "byteCount_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoBlockCipher;I", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "calculateByte", "B", "LLibOrgBouncycastleCryptoDataLengthException;LJavaLangIllegalStateException;", "encryptByte", "decryptByte", "processBlock", "[BI[BI", "encryptBlock", "decryptBlock", "cipher" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoModesCFBBlockCipher = { "CFBBlockCipher", "lib.org.bouncycastle.crypto.modes", ptrTable, methods, fields, 7, 0x1, 12, 8, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoModesCFBBlockCipher;
}

@end

void LibOrgBouncycastleCryptoModesCFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_(LibOrgBouncycastleCryptoModesCFBBlockCipher *self, id<LibOrgBouncycastleCryptoBlockCipher> cipher, jint bitBlockSize) {
  LibOrgBouncycastleCryptoStreamBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, cipher);
  self->cipher_CFBBlockCipher_ = nil;
  self->cipher_CFBBlockCipher_ = cipher;
  self->blockSize_ = bitBlockSize / 8;
  self->IV_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher)) getBlockSize]];
  self->cfbV_ = [IOSByteArray newArrayWithLength:[cipher getBlockSize]];
  self->cfbOutV_ = [IOSByteArray newArrayWithLength:[cipher getBlockSize]];
  self->inBuf_ = [IOSByteArray newArrayWithLength:self->blockSize_];
}

LibOrgBouncycastleCryptoModesCFBBlockCipher *new_LibOrgBouncycastleCryptoModesCFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_(id<LibOrgBouncycastleCryptoBlockCipher> cipher, jint bitBlockSize) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoModesCFBBlockCipher, initWithLibOrgBouncycastleCryptoBlockCipher_withInt_, cipher, bitBlockSize)
}

LibOrgBouncycastleCryptoModesCFBBlockCipher *create_LibOrgBouncycastleCryptoModesCFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_(id<LibOrgBouncycastleCryptoBlockCipher> cipher, jint bitBlockSize) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoModesCFBBlockCipher, initWithLibOrgBouncycastleCryptoBlockCipher_withInt_, cipher, bitBlockSize)
}

jbyte LibOrgBouncycastleCryptoModesCFBBlockCipher_encryptByteWithByte_(LibOrgBouncycastleCryptoModesCFBBlockCipher *self, jbyte inArg) {
  if (self->byteCount_ == 0) {
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_CFBBlockCipher_)) processBlockWithByteArray:self->cfbV_ withInt:0 withByteArray:self->cfbOutV_ withInt:0];
  }
  jbyte rv = (jbyte) (IOSByteArray_Get(nil_chk(self->cfbOutV_), self->byteCount_) ^ inArg);
  *IOSByteArray_GetRef(nil_chk(self->inBuf_), self->byteCount_++) = rv;
  if (self->byteCount_ == self->blockSize_) {
    self->byteCount_ = 0;
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->cfbV_, self->blockSize_, self->cfbV_, 0, ((IOSByteArray *) nil_chk(self->cfbV_))->size_ - self->blockSize_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->inBuf_, 0, self->cfbV_, ((IOSByteArray *) nil_chk(self->cfbV_))->size_ - self->blockSize_, self->blockSize_);
  }
  return rv;
}

jbyte LibOrgBouncycastleCryptoModesCFBBlockCipher_decryptByteWithByte_(LibOrgBouncycastleCryptoModesCFBBlockCipher *self, jbyte inArg) {
  if (self->byteCount_ == 0) {
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_CFBBlockCipher_)) processBlockWithByteArray:self->cfbV_ withInt:0 withByteArray:self->cfbOutV_ withInt:0];
  }
  *IOSByteArray_GetRef(nil_chk(self->inBuf_), self->byteCount_) = inArg;
  jbyte rv = (jbyte) (IOSByteArray_Get(nil_chk(self->cfbOutV_), self->byteCount_++) ^ inArg);
  if (self->byteCount_ == self->blockSize_) {
    self->byteCount_ = 0;
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->cfbV_, self->blockSize_, self->cfbV_, 0, ((IOSByteArray *) nil_chk(self->cfbV_))->size_ - self->blockSize_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->inBuf_, 0, self->cfbV_, ((IOSByteArray *) nil_chk(self->cfbV_))->size_ - self->blockSize_, self->blockSize_);
  }
  return rv;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoModesCFBBlockCipher)