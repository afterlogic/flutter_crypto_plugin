//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/OpenPGPCFBBlockCipher.java
//

#include "BlockCipher.h"
#include "CipherParameters.h"
#include "DataLengthException.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "OpenPGPCFBBlockCipher.h"
#include "OutputLengthException.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher () {
 @public
  IOSByteArray *IV_;
  IOSByteArray *FR_;
  IOSByteArray *FRE_;
  id<LibOrgBouncycastleCryptoBlockCipher> cipher_;
  jint count_;
  jint blockSize_;
  jboolean forEncryption_;
}

- (jbyte)encryptByteWithByte:(jbyte)data
                     withInt:(jint)blockOff;

- (jint)encryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (jint)decryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher, IV_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher, FR_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher, FRE_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher, cipher_, id<LibOrgBouncycastleCryptoBlockCipher>)

__attribute__((unused)) static jbyte LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher *self, jbyte data, jint blockOff);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptBlockWithByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_decryptBlockWithByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff);

@implementation LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher

- (instancetype)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)cipher {
  LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, cipher);
  return self;
}

- (id<LibOrgBouncycastleCryptoBlockCipher>)getUnderlyingCipher {
  return cipher_;
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$$", [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher_)) getAlgorithmName], @"/OpenPGPCFB");
}

- (jint)getBlockSize {
  return [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher_)) getBlockSize];
}

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  return (forEncryption_) ? LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff) : LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_decryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff);
}

- (void)reset {
  count_ = 0;
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(IV_, 0, FR_, 0, ((IOSByteArray *) nil_chk(FR_))->size_);
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher_)) reset];
}

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  self->forEncryption_ = forEncryption;
  [self reset];
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:params];
}

- (jbyte)encryptByteWithByte:(jbyte)data
                     withInt:(jint)blockOff {
  return LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, data, blockOff);
}

- (jint)encryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  return LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff);
}

- (jint)decryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  return LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_decryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoBlockCipher;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, 6, -1, -1, -1 },
    { NULL, "B", 0x2, 7, 8, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 9, 2, 3, -1, -1, -1 },
    { NULL, "I", 0x2, 10, 2, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoBlockCipher:);
  methods[1].selector = @selector(getUnderlyingCipher);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(getBlockSize);
  methods[4].selector = @selector(processBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[5].selector = @selector(reset);
  methods[6].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[7].selector = @selector(encryptByteWithByte:withInt:);
  methods[8].selector = @selector(encryptBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[9].selector = @selector(decryptBlockWithByteArray:withInt:withByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "IV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "FR_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "FRE_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cipher_", "LLibOrgBouncycastleCryptoBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "count_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "blockSize_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forEncryption_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoBlockCipher;", "processBlock", "[BI[BI", "LLibOrgBouncycastleCryptoDataLengthException;LJavaLangIllegalStateException;", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "encryptByte", "BI", "encryptBlock", "decryptBlock" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher = { "OpenPGPCFBBlockCipher", "lib.org.bouncycastle.crypto.modes", ptrTable, methods, fields, 7, 0x1, 10, 7, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher;
}

@end

void LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher *self, id<LibOrgBouncycastleCryptoBlockCipher> cipher) {
  NSObject_init(self);
  self->cipher_ = cipher;
  self->blockSize_ = [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher)) getBlockSize];
  self->IV_ = [IOSByteArray newArrayWithLength:self->blockSize_];
  self->FR_ = [IOSByteArray newArrayWithLength:self->blockSize_];
  self->FRE_ = [IOSByteArray newArrayWithLength:self->blockSize_];
}

LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher *new_LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher, initWithLibOrgBouncycastleCryptoBlockCipher_, cipher)
}

LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher *create_LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher, initWithLibOrgBouncycastleCryptoBlockCipher_, cipher)
}

jbyte LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher *self, jbyte data, jint blockOff) {
  return (jbyte) (IOSByteArray_Get(nil_chk(self->FRE_), blockOff) ^ data);
}

jint LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptBlockWithByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff) {
  if ((inOff + self->blockSize_) > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if ((outOff + self->blockSize_) > ((IOSByteArray *) nil_chk(outArg))->size_) {
    @throw new_LibOrgBouncycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  if (self->count_ > self->blockSize_) {
    *IOSByteArray_GetRef(nil_chk(self->FR_), self->blockSize_ - 2) = *IOSByteArray_GetRef(outArg, outOff) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(inArg, inOff), self->blockSize_ - 2);
    *IOSByteArray_GetRef(nil_chk(self->FR_), self->blockSize_ - 1) = *IOSByteArray_GetRef(outArg, outOff + 1) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(inArg, inOff + 1), self->blockSize_ - 1);
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    for (jint n = 2; n < self->blockSize_; n++) {
      *IOSByteArray_GetRef(nil_chk(self->FR_), n - 2) = *IOSByteArray_GetRef(outArg, outOff + n) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(inArg, inOff + n), n - 2);
    }
  }
  else if (self->count_ == 0) {
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    for (jint n = 0; n < self->blockSize_; n++) {
      *IOSByteArray_GetRef(nil_chk(self->FR_), n) = *IOSByteArray_GetRef(outArg, outOff + n) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(inArg, inOff + n), n);
    }
    self->count_ += self->blockSize_;
  }
  else if (self->count_ == self->blockSize_) {
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    *IOSByteArray_GetRef(outArg, outOff) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(inArg, inOff), 0);
    *IOSByteArray_GetRef(outArg, outOff + 1) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(inArg, inOff + 1), 1);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->FR_, 2, self->FR_, 0, self->blockSize_ - 2);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(outArg, outOff, self->FR_, self->blockSize_ - 2, 2);
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    for (jint n = 2; n < self->blockSize_; n++) {
      *IOSByteArray_GetRef(nil_chk(self->FR_), n - 2) = *IOSByteArray_GetRef(outArg, outOff + n) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(inArg, inOff + n), n - 2);
    }
    self->count_ += self->blockSize_;
  }
  return self->blockSize_;
}

jint LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_decryptBlockWithByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff) {
  if ((inOff + self->blockSize_) > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if ((outOff + self->blockSize_) > ((IOSByteArray *) nil_chk(outArg))->size_) {
    @throw new_LibOrgBouncycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  if (self->count_ > self->blockSize_) {
    jbyte inVal = IOSByteArray_Get(inArg, inOff);
    *IOSByteArray_GetRef(nil_chk(self->FR_), self->blockSize_ - 2) = inVal;
    *IOSByteArray_GetRef(outArg, outOff) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, inVal, self->blockSize_ - 2);
    inVal = IOSByteArray_Get(inArg, inOff + 1);
    *IOSByteArray_GetRef(nil_chk(self->FR_), self->blockSize_ - 1) = inVal;
    *IOSByteArray_GetRef(outArg, outOff + 1) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, inVal, self->blockSize_ - 1);
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    for (jint n = 2; n < self->blockSize_; n++) {
      inVal = IOSByteArray_Get(inArg, inOff + n);
      *IOSByteArray_GetRef(nil_chk(self->FR_), n - 2) = inVal;
      *IOSByteArray_GetRef(outArg, outOff + n) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, inVal, n - 2);
    }
  }
  else if (self->count_ == 0) {
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    for (jint n = 0; n < self->blockSize_; n++) {
      *IOSByteArray_GetRef(nil_chk(self->FR_), n) = IOSByteArray_Get(inArg, inOff + n);
      *IOSByteArray_GetRef(outArg, n) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(inArg, inOff + n), n);
    }
    self->count_ += self->blockSize_;
  }
  else if (self->count_ == self->blockSize_) {
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    jbyte inVal1 = IOSByteArray_Get(inArg, inOff);
    jbyte inVal2 = IOSByteArray_Get(inArg, inOff + 1);
    *IOSByteArray_GetRef(outArg, outOff) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, inVal1, 0);
    *IOSByteArray_GetRef(outArg, outOff + 1) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, inVal2, 1);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->FR_, 2, self->FR_, 0, self->blockSize_ - 2);
    *IOSByteArray_GetRef(nil_chk(self->FR_), self->blockSize_ - 2) = inVal1;
    *IOSByteArray_GetRef(self->FR_, self->blockSize_ - 1) = inVal2;
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    for (jint n = 2; n < self->blockSize_; n++) {
      jbyte inVal = IOSByteArray_Get(inArg, inOff + n);
      *IOSByteArray_GetRef(nil_chk(self->FR_), n - 2) = inVal;
      *IOSByteArray_GetRef(outArg, outOff + n) = LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, inVal, n - 2);
    }
    self->count_ += self->blockSize_;
  }
  return self->blockSize_;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoModesOpenPGPCFBBlockCipher)