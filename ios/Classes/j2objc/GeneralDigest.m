//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/GeneralDigest.java
//

#include "GeneralDigest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Pack.h"
#include "java/lang/Math.h"
#include "java/lang/System.h"

#pragma clang diagnostic ignored "-Wprotocol"

@interface LibOrgBouncycastleCryptoDigestsGeneralDigest () {
 @public
  IOSByteArray *xBuf_;
  jint xBufOff_;
  jlong byteCount_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGeneralDigest, xBuf_, IOSByteArray *)

inline jint LibOrgBouncycastleCryptoDigestsGeneralDigest_get_BYTE_LENGTH(void);
#define LibOrgBouncycastleCryptoDigestsGeneralDigest_BYTE_LENGTH 64
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoDigestsGeneralDigest, BYTE_LENGTH, jint)

@implementation LibOrgBouncycastleCryptoDigestsGeneralDigest

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoDigestsGeneralDigest_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleCryptoDigestsGeneralDigest:(LibOrgBouncycastleCryptoDigestsGeneralDigest *)t {
  LibOrgBouncycastleCryptoDigestsGeneralDigest_initWithLibOrgBouncycastleCryptoDigestsGeneralDigest_(self, t);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)encodedState {
  LibOrgBouncycastleCryptoDigestsGeneralDigest_initWithByteArray_(self, encodedState);
  return self;
}

- (void)copyInWithLibOrgBouncycastleCryptoDigestsGeneralDigest:(LibOrgBouncycastleCryptoDigestsGeneralDigest *)t {
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(((LibOrgBouncycastleCryptoDigestsGeneralDigest *) nil_chk(t))->xBuf_, 0, xBuf_, 0, ((IOSByteArray *) nil_chk(t->xBuf_))->size_);
  xBufOff_ = t->xBufOff_;
  byteCount_ = t->byteCount_;
}

- (void)updateWithByte:(jbyte)inArg {
  *IOSByteArray_GetRef(nil_chk(xBuf_), xBufOff_++) = inArg;
  if (xBufOff_ == xBuf_->size_) {
    [self processWordWithByteArray:xBuf_ withInt:0];
    xBufOff_ = 0;
  }
  byteCount_++;
}

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len {
  len = JavaLangMath_maxWithInt_withInt_(0, len);
  jint i = 0;
  if (xBufOff_ != 0) {
    while (i < len) {
      *IOSByteArray_GetRef(nil_chk(xBuf_), xBufOff_++) = IOSByteArray_Get(nil_chk(inArg), inOff + i++);
      if (xBufOff_ == 4) {
        [self processWordWithByteArray:xBuf_ withInt:0];
        xBufOff_ = 0;
        break;
      }
    }
  }
  jint limit = ((len - i) & ~3) + i;
  for (; i < limit; i += 4) {
    [self processWordWithByteArray:inArg withInt:inOff + i];
  }
  while (i < len) {
    *IOSByteArray_GetRef(nil_chk(xBuf_), xBufOff_++) = IOSByteArray_Get(nil_chk(inArg), inOff + i++);
  }
  byteCount_ += len;
}

- (void)finish {
  jlong bitLength = (JreLShift64(byteCount_, 3));
  [self updateWithByte:(jbyte) 128];
  while (xBufOff_ != 0) {
    [self updateWithByte:(jbyte) 0];
  }
  [self processLengthWithLong:bitLength];
  [self processBlock];
}

- (void)reset {
  byteCount_ = 0;
  xBufOff_ = 0;
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(xBuf_))->size_; i++) {
    *IOSByteArray_GetRef(xBuf_, i) = 0;
  }
}

- (void)populateStateWithByteArray:(IOSByteArray *)state {
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(xBuf_, 0, state, 0, xBufOff_);
  LibOrgBouncycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(xBufOff_, state, 4);
  LibOrgBouncycastleUtilPack_longToBigEndianWithLong_withByteArray_withInt_(byteCount_, state, 8);
}

- (jint)getByteLength {
  return LibOrgBouncycastleCryptoDigestsGeneralDigest_BYTE_LENGTH;
}

- (void)processWordWithByteArray:(IOSByteArray *)inArg
                         withInt:(jint)inOff {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

- (void)processLengthWithLong:(jlong)bitLength {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

- (void)processBlock {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 2, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 6, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x404, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x404, 9, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x404, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoDigestsGeneralDigest:);
  methods[2].selector = @selector(initWithByteArray:);
  methods[3].selector = @selector(copyInWithLibOrgBouncycastleCryptoDigestsGeneralDigest:);
  methods[4].selector = @selector(updateWithByte:);
  methods[5].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[6].selector = @selector(finish);
  methods[7].selector = @selector(reset);
  methods[8].selector = @selector(populateStateWithByteArray:);
  methods[9].selector = @selector(getByteLength);
  methods[10].selector = @selector(processWordWithByteArray:withInt:);
  methods[11].selector = @selector(processLengthWithLong:);
  methods[12].selector = @selector(processBlock);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "BYTE_LENGTH", "I", .constantValue.asInt = LibOrgBouncycastleCryptoDigestsGeneralDigest_BYTE_LENGTH, 0x1a, -1, -1, -1, -1 },
    { "xBuf_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "xBufOff_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "byteCount_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigestsGeneralDigest;", "[B", "copyIn", "update", "B", "[BII", "populateState", "processWord", "[BI", "processLength", "J" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoDigestsGeneralDigest = { "GeneralDigest", "lib.org.bouncycastle.crypto.digests", ptrTable, methods, fields, 7, 0x401, 13, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoDigestsGeneralDigest;
}

@end

void LibOrgBouncycastleCryptoDigestsGeneralDigest_init(LibOrgBouncycastleCryptoDigestsGeneralDigest *self) {
  NSObject_init(self);
  self->xBuf_ = [IOSByteArray newArrayWithLength:4];
  self->xBufOff_ = 0;
}

void LibOrgBouncycastleCryptoDigestsGeneralDigest_initWithLibOrgBouncycastleCryptoDigestsGeneralDigest_(LibOrgBouncycastleCryptoDigestsGeneralDigest *self, LibOrgBouncycastleCryptoDigestsGeneralDigest *t) {
  NSObject_init(self);
  self->xBuf_ = [IOSByteArray newArrayWithLength:4];
  [self copyInWithLibOrgBouncycastleCryptoDigestsGeneralDigest:t];
}

void LibOrgBouncycastleCryptoDigestsGeneralDigest_initWithByteArray_(LibOrgBouncycastleCryptoDigestsGeneralDigest *self, IOSByteArray *encodedState) {
  NSObject_init(self);
  self->xBuf_ = [IOSByteArray newArrayWithLength:4];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(encodedState, 0, self->xBuf_, 0, self->xBuf_->size_);
  self->xBufOff_ = LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(encodedState, 4);
  self->byteCount_ = LibOrgBouncycastleUtilPack_bigEndianToLongWithByteArray_withInt_(encodedState, 8);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoDigestsGeneralDigest)
