//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/ISO9796d2Signer.java
//

#include "Arrays.h"
#include "AsymmetricBlockCipher.h"
#include "CipherParameters.h"
#include "Digest.h"
#include "IOSPrimitiveArray.h"
#include "ISO9796d2Signer.h"
#include "ISOTrailers.h"
#include "InvalidCipherTextException.h"
#include "J2ObjC_source.h"
#include "RSAKeyParameters.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/Integer.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoSignersISO9796d2Signer () {
 @public
  id<LibOrgBouncycastleCryptoDigest> digest_;
  id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher_;
  jint trailer_;
  jint keyBits_;
  IOSByteArray *block_;
  IOSByteArray *mBuf_;
  jint messageLength_;
  jboolean fullMessage_;
  IOSByteArray *recoveredMessage_;
  IOSByteArray *preSig_;
  IOSByteArray *preBlock_;
}

- (jboolean)isSameAsWithByteArray:(IOSByteArray *)a
                    withByteArray:(IOSByteArray *)b;

- (void)clearBlockWithByteArray:(IOSByteArray *)block;

- (jboolean)returnFalseWithByteArray:(IOSByteArray *)block;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersISO9796d2Signer, digest_, id<LibOrgBouncycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersISO9796d2Signer, cipher_, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersISO9796d2Signer, block_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersISO9796d2Signer, mBuf_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersISO9796d2Signer, recoveredMessage_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersISO9796d2Signer, preSig_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersISO9796d2Signer, preBlock_, IOSByteArray *)

__attribute__((unused)) static jboolean LibOrgBouncycastleCryptoSignersISO9796d2Signer_isSameAsWithByteArray_withByteArray_(LibOrgBouncycastleCryptoSignersISO9796d2Signer *self, IOSByteArray *a, IOSByteArray *b);

__attribute__((unused)) static void LibOrgBouncycastleCryptoSignersISO9796d2Signer_clearBlockWithByteArray_(LibOrgBouncycastleCryptoSignersISO9796d2Signer *self, IOSByteArray *block);

__attribute__((unused)) static jboolean LibOrgBouncycastleCryptoSignersISO9796d2Signer_returnFalseWithByteArray_(LibOrgBouncycastleCryptoSignersISO9796d2Signer *self, IOSByteArray *block);

@implementation LibOrgBouncycastleCryptoSignersISO9796d2Signer

+ (jint)TRAILER_IMPLICIT {
  return LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_IMPLICIT;
}

+ (jint)TRAILER_RIPEMD160 {
  return LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_RIPEMD160;
}

+ (jint)TRAILER_RIPEMD128 {
  return LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_RIPEMD128;
}

+ (jint)TRAILER_SHA1 {
  return LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_SHA1;
}

+ (jint)TRAILER_SHA256 {
  return LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_SHA256;
}

+ (jint)TRAILER_SHA512 {
  return LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_SHA512;
}

+ (jint)TRAILER_SHA384 {
  return LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_SHA384;
}

+ (jint)TRAILER_WHIRLPOOL {
  return LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_WHIRLPOOL;
}

- (instancetype)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)cipher
                                   withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                                          withBoolean:(jboolean)implicit {
  LibOrgBouncycastleCryptoSignersISO9796d2Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_withBoolean_(self, cipher, digest, implicit);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)cipher
                                   withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest {
  LibOrgBouncycastleCryptoSignersISO9796d2Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(self, cipher, digest);
  return self;
}

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param {
  LibOrgBouncycastleCryptoParamsRSAKeyParameters *kParam = (LibOrgBouncycastleCryptoParamsRSAKeyParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsRSAKeyParameters class]);
  [((id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>) nil_chk(cipher_)) init__WithBoolean:forSigning withLibOrgBouncycastleCryptoCipherParameters:kParam];
  keyBits_ = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(kParam)) getModulus])) bitLength];
  block_ = [IOSByteArray newArrayWithLength:(keyBits_ + 7) / 8];
  if (trailer_ == LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_IMPLICIT) {
    mBuf_ = [IOSByteArray newArrayWithLength:block_->size_ - [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize] - 2];
  }
  else {
    mBuf_ = [IOSByteArray newArrayWithLength:block_->size_ - [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize] - 3];
  }
  [self reset];
}

- (jboolean)isSameAsWithByteArray:(IOSByteArray *)a
                    withByteArray:(IOSByteArray *)b {
  return LibOrgBouncycastleCryptoSignersISO9796d2Signer_isSameAsWithByteArray_withByteArray_(self, a, b);
}

- (void)clearBlockWithByteArray:(IOSByteArray *)block {
  LibOrgBouncycastleCryptoSignersISO9796d2Signer_clearBlockWithByteArray_(self, block);
}

- (void)updateWithRecoveredMessageWithByteArray:(IOSByteArray *)signature {
  IOSByteArray *block = [((id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>) nil_chk(cipher_)) processBlockWithByteArray:signature withInt:0 withInt:((IOSByteArray *) nil_chk(signature))->size_];
  if (((IOSByteArray_Get(nil_chk(block), 0) & (jint) 0xC0) ^ (jint) 0x40) != 0) {
    @throw new_LibOrgBouncycastleCryptoInvalidCipherTextException_initWithNSString_(@"malformed signature");
  }
  if (((IOSByteArray_Get(block, block->size_ - 1) & (jint) 0xF) ^ (jint) 0xC) != 0) {
    @throw new_LibOrgBouncycastleCryptoInvalidCipherTextException_initWithNSString_(@"malformed signature");
  }
  jint delta = 0;
  if (((IOSByteArray_Get(block, block->size_ - 1) & (jint) 0xFF) ^ (jint) 0xBC) == 0) {
    delta = 1;
  }
  else {
    jint sigTrail = (JreLShift32((IOSByteArray_Get(block, block->size_ - 2) & (jint) 0xFF), 8)) | (IOSByteArray_Get(block, block->size_ - 1) & (jint) 0xFF);
    JavaLangInteger *trailerObj = LibOrgBouncycastleCryptoSignersISOTrailers_getTrailerWithLibOrgBouncycastleCryptoDigest_(digest_);
    if (trailerObj != nil) {
      jint trailer = [trailerObj intValue];
      if (sigTrail != trailer) {
        if (!(trailer == LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_SHA512_256 && sigTrail == (jint) 0x40CC)) {
          @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$I", @"signer initialised with wrong digest for trailer ", sigTrail));
        }
      }
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unrecognised hash in signature");
    }
    delta = 2;
  }
  jint mStart = 0;
  for (mStart = 0; mStart != block->size_; mStart++) {
    if (((IOSByteArray_Get(block, mStart) & (jint) 0x0f) ^ (jint) 0x0a) == 0) {
      break;
    }
  }
  mStart++;
  jint off = block->size_ - delta - [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize];
  if ((off - mStart) <= 0) {
    @throw new_LibOrgBouncycastleCryptoInvalidCipherTextException_initWithNSString_(@"malformed block");
  }
  if ((IOSByteArray_Get(block, 0) & (jint) 0x20) == 0) {
    fullMessage_ = true;
    recoveredMessage_ = [IOSByteArray newArrayWithLength:off - mStart];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(block, mStart, recoveredMessage_, 0, recoveredMessage_->size_);
  }
  else {
    fullMessage_ = false;
    recoveredMessage_ = [IOSByteArray newArrayWithLength:off - mStart];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(block, mStart, recoveredMessage_, 0, recoveredMessage_->size_);
  }
  preSig_ = signature;
  preBlock_ = block;
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:recoveredMessage_ withInt:0 withInt:((IOSByteArray *) nil_chk(recoveredMessage_))->size_];
  messageLength_ = ((IOSByteArray *) nil_chk(recoveredMessage_))->size_;
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(recoveredMessage_, 0, mBuf_, 0, recoveredMessage_->size_);
}

- (void)updateWithByte:(jbyte)b {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByte:b];
  if (messageLength_ < ((IOSByteArray *) nil_chk(mBuf_))->size_) {
    *IOSByteArray_GetRef(mBuf_, messageLength_) = b;
  }
  messageLength_++;
}

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)off
                    withInt:(jint)len {
  while (len > 0 && messageLength_ < ((IOSByteArray *) nil_chk(mBuf_))->size_) {
    [self updateWithByte:IOSByteArray_Get(nil_chk(inArg), off)];
    off++;
    len--;
  }
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:inArg withInt:off withInt:len];
  messageLength_ += len;
}

- (void)reset {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) reset];
  messageLength_ = 0;
  LibOrgBouncycastleCryptoSignersISO9796d2Signer_clearBlockWithByteArray_(self, mBuf_);
  if (recoveredMessage_ != nil) {
    LibOrgBouncycastleCryptoSignersISO9796d2Signer_clearBlockWithByteArray_(self, recoveredMessage_);
  }
  recoveredMessage_ = nil;
  fullMessage_ = false;
  if (preSig_ != nil) {
    preSig_ = nil;
    LibOrgBouncycastleCryptoSignersISO9796d2Signer_clearBlockWithByteArray_(self, preBlock_);
    preBlock_ = nil;
  }
}

- (IOSByteArray *)generateSignature {
  jint digSize = [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize];
  jint t = 0;
  jint delta = 0;
  if (trailer_ == LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_IMPLICIT) {
    t = 8;
    delta = ((IOSByteArray *) nil_chk(block_))->size_ - digSize - 1;
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:block_ withInt:delta];
    *IOSByteArray_GetRef(block_, ((IOSByteArray *) nil_chk(block_))->size_ - 1) = (jbyte) LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_IMPLICIT;
  }
  else {
    t = 16;
    delta = ((IOSByteArray *) nil_chk(block_))->size_ - digSize - 2;
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:block_ withInt:delta];
    *IOSByteArray_GetRef(block_, ((IOSByteArray *) nil_chk(block_))->size_ - 2) = (jbyte) (JreURShift32(trailer_, 8));
    *IOSByteArray_GetRef(block_, block_->size_ - 1) = (jbyte) trailer_;
  }
  jbyte header = 0;
  jint x = (digSize + messageLength_) * 8 + t + 4 - keyBits_;
  if (x > 0) {
    jint mR = messageLength_ - ((x + 7) / 8);
    header = (jint) 0x60;
    delta -= mR;
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(mBuf_, 0, block_, delta, mR);
    recoveredMessage_ = [IOSByteArray newArrayWithLength:mR];
  }
  else {
    header = (jint) 0x40;
    delta -= messageLength_;
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(mBuf_, 0, block_, delta, messageLength_);
    recoveredMessage_ = [IOSByteArray newArrayWithLength:messageLength_];
  }
  if ((delta - 1) > 0) {
    for (jint i = delta - 1; i != 0; i--) {
      *IOSByteArray_GetRef(nil_chk(block_), i) = (jbyte) (jint) 0xbb;
    }
    *IOSByteArray_GetRef(nil_chk(block_), delta - 1) ^= (jbyte) (jint) 0x01;
    *IOSByteArray_GetRef(block_, 0) = (jbyte) (jint) 0x0b;
    *IOSByteArray_GetRef(block_, 0) |= header;
  }
  else {
    *IOSByteArray_GetRef(nil_chk(block_), 0) = (jbyte) (jint) 0x0a;
    *IOSByteArray_GetRef(block_, 0) |= header;
  }
  IOSByteArray *b = [((id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>) nil_chk(cipher_)) processBlockWithByteArray:block_ withInt:0 withInt:block_->size_];
  fullMessage_ = ((header & (jint) 0x20) == 0);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(mBuf_, 0, recoveredMessage_, 0, ((IOSByteArray *) nil_chk(recoveredMessage_))->size_);
  messageLength_ = 0;
  LibOrgBouncycastleCryptoSignersISO9796d2Signer_clearBlockWithByteArray_(self, mBuf_);
  LibOrgBouncycastleCryptoSignersISO9796d2Signer_clearBlockWithByteArray_(self, block_);
  return b;
}

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)signature {
  IOSByteArray *block = nil;
  if (preSig_ == nil) {
    @try {
      block = [((id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>) nil_chk(cipher_)) processBlockWithByteArray:signature withInt:0 withInt:((IOSByteArray *) nil_chk(signature))->size_];
    }
    @catch (JavaLangException *e) {
      return false;
    }
  }
  else {
    if (!LibOrgBouncycastleUtilArrays_areEqualWithByteArray_withByteArray_(preSig_, signature)) {
      @throw new_JavaLangIllegalStateException_initWithNSString_(@"updateWithRecoveredMessage called on different signature");
    }
    block = preBlock_;
    preSig_ = nil;
    preBlock_ = nil;
  }
  if (((IOSByteArray_Get(nil_chk(block), 0) & (jint) 0xC0) ^ (jint) 0x40) != 0) {
    return LibOrgBouncycastleCryptoSignersISO9796d2Signer_returnFalseWithByteArray_(self, block);
  }
  if (((IOSByteArray_Get(block, block->size_ - 1) & (jint) 0xF) ^ (jint) 0xC) != 0) {
    return LibOrgBouncycastleCryptoSignersISO9796d2Signer_returnFalseWithByteArray_(self, block);
  }
  jint delta = 0;
  if (((IOSByteArray_Get(block, block->size_ - 1) & (jint) 0xFF) ^ (jint) 0xBC) == 0) {
    delta = 1;
  }
  else {
    jint sigTrail = (JreLShift32((IOSByteArray_Get(block, block->size_ - 2) & (jint) 0xFF), 8)) | (IOSByteArray_Get(block, block->size_ - 1) & (jint) 0xFF);
    JavaLangInteger *trailerObj = LibOrgBouncycastleCryptoSignersISOTrailers_getTrailerWithLibOrgBouncycastleCryptoDigest_(digest_);
    if (trailerObj != nil) {
      jint trailer = [trailerObj intValue];
      if (sigTrail != trailer) {
        if (!(trailer == LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_SHA512_256 && sigTrail == (jint) 0x40CC)) {
          @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$I", @"signer initialised with wrong digest for trailer ", sigTrail));
        }
      }
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unrecognised hash in signature");
    }
    delta = 2;
  }
  jint mStart = 0;
  for (mStart = 0; mStart != block->size_; mStart++) {
    if (((IOSByteArray_Get(block, mStart) & (jint) 0x0f) ^ (jint) 0x0a) == 0) {
      break;
    }
  }
  mStart++;
  IOSByteArray *hash_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize]];
  jint off = block->size_ - delta - hash_->size_;
  if ((off - mStart) <= 0) {
    return LibOrgBouncycastleCryptoSignersISO9796d2Signer_returnFalseWithByteArray_(self, block);
  }
  if ((IOSByteArray_Get(block, 0) & (jint) 0x20) == 0) {
    fullMessage_ = true;
    if (messageLength_ > off - mStart) {
      return LibOrgBouncycastleCryptoSignersISO9796d2Signer_returnFalseWithByteArray_(self, block);
    }
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) reset];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:block withInt:mStart withInt:off - mStart];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:hash_ withInt:0];
    jboolean isOkay = true;
    for (jint i = 0; i != hash_->size_; i++) {
      *IOSByteArray_GetRef(block, off + i) ^= IOSByteArray_Get(hash_, i);
      if (IOSByteArray_Get(block, off + i) != 0) {
        isOkay = false;
      }
    }
    if (!isOkay) {
      return LibOrgBouncycastleCryptoSignersISO9796d2Signer_returnFalseWithByteArray_(self, block);
    }
    recoveredMessage_ = [IOSByteArray newArrayWithLength:off - mStart];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(block, mStart, recoveredMessage_, 0, recoveredMessage_->size_);
  }
  else {
    fullMessage_ = false;
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:hash_ withInt:0];
    jboolean isOkay = true;
    for (jint i = 0; i != hash_->size_; i++) {
      *IOSByteArray_GetRef(block, off + i) ^= IOSByteArray_Get(hash_, i);
      if (IOSByteArray_Get(block, off + i) != 0) {
        isOkay = false;
      }
    }
    if (!isOkay) {
      return LibOrgBouncycastleCryptoSignersISO9796d2Signer_returnFalseWithByteArray_(self, block);
    }
    recoveredMessage_ = [IOSByteArray newArrayWithLength:off - mStart];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(block, mStart, recoveredMessage_, 0, recoveredMessage_->size_);
  }
  if (messageLength_ != 0) {
    if (!LibOrgBouncycastleCryptoSignersISO9796d2Signer_isSameAsWithByteArray_withByteArray_(self, mBuf_, recoveredMessage_)) {
      return LibOrgBouncycastleCryptoSignersISO9796d2Signer_returnFalseWithByteArray_(self, block);
    }
  }
  LibOrgBouncycastleCryptoSignersISO9796d2Signer_clearBlockWithByteArray_(self, mBuf_);
  LibOrgBouncycastleCryptoSignersISO9796d2Signer_clearBlockWithByteArray_(self, block);
  messageLength_ = 0;
  return true;
}

- (jboolean)returnFalseWithByteArray:(IOSByteArray *)block {
  return LibOrgBouncycastleCryptoSignersISO9796d2Signer_returnFalseWithByteArray_(self, block);
}

- (jboolean)hasFullMessage {
  return fullMessage_;
}

- (IOSByteArray *)getRecoveredMessage {
  return recoveredMessage_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 8, 7, 9, -1, -1, -1 },
    { NULL, "V", 0x1, 10, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 10, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 13, -1, -1, -1 },
    { NULL, "Z", 0x1, 14, 7, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 15, 7, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:withLibOrgBouncycastleCryptoDigest:withBoolean:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:withLibOrgBouncycastleCryptoDigest:);
  methods[2].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[3].selector = @selector(isSameAsWithByteArray:withByteArray:);
  methods[4].selector = @selector(clearBlockWithByteArray:);
  methods[5].selector = @selector(updateWithRecoveredMessageWithByteArray:);
  methods[6].selector = @selector(updateWithByte:);
  methods[7].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[8].selector = @selector(reset);
  methods[9].selector = @selector(generateSignature);
  methods[10].selector = @selector(verifySignatureWithByteArray:);
  methods[11].selector = @selector(returnFalseWithByteArray:);
  methods[12].selector = @selector(hasFullMessage);
  methods[13].selector = @selector(getRecoveredMessage);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "TRAILER_IMPLICIT", "I", .constantValue.asInt = LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_IMPLICIT, 0x19, -1, -1, -1, -1 },
    { "TRAILER_RIPEMD160", "I", .constantValue.asInt = LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_RIPEMD160, 0x19, -1, -1, -1, -1 },
    { "TRAILER_RIPEMD128", "I", .constantValue.asInt = LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_RIPEMD128, 0x19, -1, -1, -1, -1 },
    { "TRAILER_SHA1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_SHA1, 0x19, -1, -1, -1, -1 },
    { "TRAILER_SHA256", "I", .constantValue.asInt = LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_SHA256, 0x19, -1, -1, -1, -1 },
    { "TRAILER_SHA512", "I", .constantValue.asInt = LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_SHA512, 0x19, -1, -1, -1, -1 },
    { "TRAILER_SHA384", "I", .constantValue.asInt = LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_SHA384, 0x19, -1, -1, -1, -1 },
    { "TRAILER_WHIRLPOOL", "I", .constantValue.asInt = LibOrgBouncycastleCryptoSignersISO9796d2Signer_TRAILER_WHIRLPOOL, 0x19, -1, -1, -1, -1 },
    { "digest_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cipher_", "LLibOrgBouncycastleCryptoAsymmetricBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "trailer_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyBits_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "block_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mBuf_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "messageLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "fullMessage_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "recoveredMessage_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "preSig_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "preBlock_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoAsymmetricBlockCipher;LLibOrgBouncycastleCryptoDigest;Z", "LLibOrgBouncycastleCryptoAsymmetricBlockCipher;LLibOrgBouncycastleCryptoDigest;", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "isSameAs", "[B[B", "clearBlock", "[B", "updateWithRecoveredMessage", "LLibOrgBouncycastleCryptoInvalidCipherTextException;", "update", "B", "[BII", "LLibOrgBouncycastleCryptoCryptoException;", "verifySignature", "returnFalse" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoSignersISO9796d2Signer = { "ISO9796d2Signer", "lib.org.bouncycastle.crypto.signers", ptrTable, methods, fields, 7, 0x1, 14, 19, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoSignersISO9796d2Signer;
}

@end

void LibOrgBouncycastleCryptoSignersISO9796d2Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_withBoolean_(LibOrgBouncycastleCryptoSignersISO9796d2Signer *self, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher, id<LibOrgBouncycastleCryptoDigest> digest, jboolean implicit) {
  NSObject_init(self);
  self->cipher_ = cipher;
  self->digest_ = digest;
  if (implicit) {
    self->trailer_ = LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_IMPLICIT;
  }
  else {
    JavaLangInteger *trailerObj = LibOrgBouncycastleCryptoSignersISOTrailers_getTrailerWithLibOrgBouncycastleCryptoDigest_(digest);
    if (trailerObj != nil) {
      self->trailer_ = [trailerObj intValue];
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"no valid trailer for digest: ", [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest)) getAlgorithmName]));
    }
  }
}

LibOrgBouncycastleCryptoSignersISO9796d2Signer *new_LibOrgBouncycastleCryptoSignersISO9796d2Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_withBoolean_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher, id<LibOrgBouncycastleCryptoDigest> digest, jboolean implicit) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoSignersISO9796d2Signer, initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_withBoolean_, cipher, digest, implicit)
}

LibOrgBouncycastleCryptoSignersISO9796d2Signer *create_LibOrgBouncycastleCryptoSignersISO9796d2Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_withBoolean_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher, id<LibOrgBouncycastleCryptoDigest> digest, jboolean implicit) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoSignersISO9796d2Signer, initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_withBoolean_, cipher, digest, implicit)
}

void LibOrgBouncycastleCryptoSignersISO9796d2Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoSignersISO9796d2Signer *self, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher, id<LibOrgBouncycastleCryptoDigest> digest) {
  LibOrgBouncycastleCryptoSignersISO9796d2Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_withBoolean_(self, cipher, digest, false);
}

LibOrgBouncycastleCryptoSignersISO9796d2Signer *new_LibOrgBouncycastleCryptoSignersISO9796d2Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher, id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoSignersISO9796d2Signer, initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_, cipher, digest)
}

LibOrgBouncycastleCryptoSignersISO9796d2Signer *create_LibOrgBouncycastleCryptoSignersISO9796d2Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher, id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoSignersISO9796d2Signer, initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_, cipher, digest)
}

jboolean LibOrgBouncycastleCryptoSignersISO9796d2Signer_isSameAsWithByteArray_withByteArray_(LibOrgBouncycastleCryptoSignersISO9796d2Signer *self, IOSByteArray *a, IOSByteArray *b) {
  jboolean isOkay = true;
  if (self->messageLength_ > ((IOSByteArray *) nil_chk(self->mBuf_))->size_) {
    if (self->mBuf_->size_ > ((IOSByteArray *) nil_chk(b))->size_) {
      isOkay = false;
    }
    for (jint i = 0; i != self->mBuf_->size_; i++) {
      if (IOSByteArray_Get(nil_chk(a), i) != IOSByteArray_Get(b, i)) {
        isOkay = false;
      }
    }
  }
  else {
    if (self->messageLength_ != ((IOSByteArray *) nil_chk(b))->size_) {
      isOkay = false;
    }
    for (jint i = 0; i != b->size_; i++) {
      if (IOSByteArray_Get(nil_chk(a), i) != IOSByteArray_Get(b, i)) {
        isOkay = false;
      }
    }
  }
  return isOkay;
}

void LibOrgBouncycastleCryptoSignersISO9796d2Signer_clearBlockWithByteArray_(LibOrgBouncycastleCryptoSignersISO9796d2Signer *self, IOSByteArray *block) {
  for (jint i = 0; i != ((IOSByteArray *) nil_chk(block))->size_; i++) {
    *IOSByteArray_GetRef(block, i) = 0;
  }
}

jboolean LibOrgBouncycastleCryptoSignersISO9796d2Signer_returnFalseWithByteArray_(LibOrgBouncycastleCryptoSignersISO9796d2Signer *self, IOSByteArray *block) {
  self->messageLength_ = 0;
  LibOrgBouncycastleCryptoSignersISO9796d2Signer_clearBlockWithByteArray_(self, self->mBuf_);
  LibOrgBouncycastleCryptoSignersISO9796d2Signer_clearBlockWithByteArray_(self, block);
  return false;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoSignersISO9796d2Signer)