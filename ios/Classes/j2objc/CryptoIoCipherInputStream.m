//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/io/CryptoIoCipherInputStream.java
//

#include "AEADBlockCipher.h"
#include "Arrays.h"
#include "BufferedBlockCipher.h"
#include "CipherIOException.h"
#include "CryptoIoCipherInputStream.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "InvalidCipherTextException.h"
#include "InvalidCipherTextIOException.h"
#include "J2ObjC_source.h"
#include "SkippingCipher.h"
#include "StreamCipher.h"
#include "java/io/FilterInputStream.h"
#include "java/io/IOException.h"
#include "java/io/InputStream.h"
#include "java/lang/Exception.h"
#include "java/lang/Math.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream () {
 @public
  id<LibOrgBouncycastleCryptoSkippingCipher> skippingCipher_;
  IOSByteArray *inBuf_;
  LibOrgBouncycastleCryptoBufferedBlockCipher *bufferedBlockCipher_;
  id<LibOrgBouncycastleCryptoStreamCipher> streamCipher_;
  id<LibOrgBouncycastleCryptoModesAEADBlockCipher> aeadBlockCipher_;
  IOSByteArray *buf_;
  IOSByteArray *markBuf_;
  jint bufOff_;
  jint maxBuf_;
  jboolean finalized_;
  jlong markPosition_;
  jint markBufOff_;
}

- (jint)nextChunk;

- (void)finaliseCipher;

- (void)ensureCapacityWithInt:(jint)updateSize
                  withBoolean:(jboolean)finalOutput;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, skippingCipher_, id<LibOrgBouncycastleCryptoSkippingCipher>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, inBuf_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, bufferedBlockCipher_, LibOrgBouncycastleCryptoBufferedBlockCipher *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, streamCipher_, id<LibOrgBouncycastleCryptoStreamCipher>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, aeadBlockCipher_, id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, buf_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, markBuf_, IOSByteArray *)

inline jint LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_get_INPUT_BUF_SIZE(void);
#define LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_INPUT_BUF_SIZE 2048
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, INPUT_BUF_SIZE, jint)

__attribute__((unused)) static jint LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_nextChunk(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *self);

__attribute__((unused)) static void LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_finaliseCipher(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *self);

__attribute__((unused)) static void LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_ensureCapacityWithInt_withBoolean_(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *self, jint updateSize, jboolean finalOutput);

@implementation LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)is
withLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)cipher {
  LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoBufferedBlockCipher_(self, is, cipher);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)is
 withLibOrgBouncycastleCryptoStreamCipher:(id<LibOrgBouncycastleCryptoStreamCipher>)cipher {
  LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoStreamCipher_(self, is, cipher);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)is
withLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)cipher {
  LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoModesAEADBlockCipher_(self, is, cipher);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)is
withLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)cipher
                                  withInt:(jint)bufSize {
  LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoBufferedBlockCipher_withInt_(self, is, cipher, bufSize);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)is
 withLibOrgBouncycastleCryptoStreamCipher:(id<LibOrgBouncycastleCryptoStreamCipher>)cipher
                                  withInt:(jint)bufSize {
  LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoStreamCipher_withInt_(self, is, cipher, bufSize);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)is
withLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)cipher
                                  withInt:(jint)bufSize {
  LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withInt_(self, is, cipher, bufSize);
  return self;
}

- (jint)nextChunk {
  return LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_nextChunk(self);
}

- (void)finaliseCipher {
  LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_finaliseCipher(self);
}

- (jint)read {
  if (bufOff_ >= maxBuf_) {
    if (LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_nextChunk(self) < 0) {
      return -1;
    }
  }
  return IOSByteArray_Get(nil_chk(buf_), bufOff_++) & (jint) 0xff;
}

- (jint)readWithByteArray:(IOSByteArray *)b {
  return [self readWithByteArray:b withInt:0 withInt:((IOSByteArray *) nil_chk(b))->size_];
}

- (jint)readWithByteArray:(IOSByteArray *)b
                  withInt:(jint)off
                  withInt:(jint)len {
  if (bufOff_ >= maxBuf_) {
    if (LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_nextChunk(self) < 0) {
      return -1;
    }
  }
  jint toSupply = JavaLangMath_minWithInt_withInt_(len, [self available]);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf_, bufOff_, b, off, toSupply);
  bufOff_ += toSupply;
  return toSupply;
}

- (jlong)skipWithLong:(jlong)n {
  if (n <= 0) {
    return 0;
  }
  if (skippingCipher_ != nil) {
    jint avail = [self available];
    if (n <= avail) {
      bufOff_ += n;
      return n;
    }
    bufOff_ = maxBuf_;
    jlong skip = [((JavaIoInputStream *) nil_chk(JreLoadVolatileId(&in_))) skipWithLong:n - avail];
    jlong cSkip = [((id<LibOrgBouncycastleCryptoSkippingCipher>) nil_chk(skippingCipher_)) skipWithLong:skip];
    if (skip != cSkip) {
      @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$J$", @"Unable to skip cipher ", skip, @" bytes."));
    }
    return skip + avail;
  }
  else {
    jint skip = (jint) JavaLangMath_minWithLong_withLong_(n, [self available]);
    bufOff_ += skip;
    return skip;
  }
}

- (jint)available {
  return maxBuf_ - bufOff_;
}

- (void)ensureCapacityWithInt:(jint)updateSize
                  withBoolean:(jboolean)finalOutput {
  LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_ensureCapacityWithInt_withBoolean_(self, updateSize, finalOutput);
}

- (void)close {
  @try {
    [((JavaIoInputStream *) nil_chk(JreLoadVolatileId(&in_))) close];
  }
  @finally {
    if (!finalized_) {
      LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_finaliseCipher(self);
    }
  }
  maxBuf_ = bufOff_ = 0;
  markBufOff_ = 0;
  markPosition_ = 0;
  if (markBuf_ != nil) {
    LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(markBuf_, (jbyte) 0);
    markBuf_ = nil;
  }
  if (buf_ != nil) {
    LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(buf_, (jbyte) 0);
    buf_ = nil;
  }
  LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(inBuf_, (jbyte) 0);
}

- (void)markWithInt:(jint)readlimit {
  [((JavaIoInputStream *) nil_chk(JreLoadVolatileId(&in_))) markWithInt:readlimit];
  if (skippingCipher_ != nil) {
    markPosition_ = [skippingCipher_ getPosition];
  }
  if (buf_ != nil) {
    markBuf_ = [IOSByteArray newArrayWithLength:buf_->size_];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf_, 0, markBuf_, 0, buf_->size_);
  }
  markBufOff_ = bufOff_;
}

- (void)reset {
  if (skippingCipher_ == nil) {
    @throw new_JavaIoIOException_initWithNSString_(@"cipher must implement SkippingCipher to be used with reset()");
  }
  [((JavaIoInputStream *) nil_chk(JreLoadVolatileId(&in_))) reset];
  [((id<LibOrgBouncycastleCryptoSkippingCipher>) nil_chk(skippingCipher_)) seekToWithLong:markPosition_];
  if (markBuf_ != nil) {
    buf_ = markBuf_;
  }
  bufOff_ = markBufOff_;
}

- (jboolean)markSupported {
  if (skippingCipher_ != nil) {
    return [((JavaIoInputStream *) nil_chk(JreLoadVolatileId(&in_))) markSupported];
  }
  return false;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x2, -1, -1, 6, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, 6, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 6, -1, -1, -1 },
    { NULL, "I", 0x1, 7, 8, 6, -1, -1, -1 },
    { NULL, "I", 0x1, 7, 9, 6, -1, -1, -1 },
    { NULL, "J", 0x1, 10, 11, 6, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 6, -1, -1, -1 },
    { NULL, "V", 0x2, 12, 13, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 6, -1, -1, -1 },
    { NULL, "V", 0x1, 14, 15, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 6, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoInputStream:withLibOrgBouncycastleCryptoBufferedBlockCipher:);
  methods[1].selector = @selector(initWithJavaIoInputStream:withLibOrgBouncycastleCryptoStreamCipher:);
  methods[2].selector = @selector(initWithJavaIoInputStream:withLibOrgBouncycastleCryptoModesAEADBlockCipher:);
  methods[3].selector = @selector(initWithJavaIoInputStream:withLibOrgBouncycastleCryptoBufferedBlockCipher:withInt:);
  methods[4].selector = @selector(initWithJavaIoInputStream:withLibOrgBouncycastleCryptoStreamCipher:withInt:);
  methods[5].selector = @selector(initWithJavaIoInputStream:withLibOrgBouncycastleCryptoModesAEADBlockCipher:withInt:);
  methods[6].selector = @selector(nextChunk);
  methods[7].selector = @selector(finaliseCipher);
  methods[8].selector = @selector(read);
  methods[9].selector = @selector(readWithByteArray:);
  methods[10].selector = @selector(readWithByteArray:withInt:withInt:);
  methods[11].selector = @selector(skipWithLong:);
  methods[12].selector = @selector(available);
  methods[13].selector = @selector(ensureCapacityWithInt:withBoolean:);
  methods[14].selector = @selector(close);
  methods[15].selector = @selector(markWithInt:);
  methods[16].selector = @selector(reset);
  methods[17].selector = @selector(markSupported);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "INPUT_BUF_SIZE", "I", .constantValue.asInt = LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_INPUT_BUF_SIZE, 0x1a, -1, -1, -1, -1 },
    { "skippingCipher_", "LLibOrgBouncycastleCryptoSkippingCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "inBuf_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "bufferedBlockCipher_", "LLibOrgBouncycastleCryptoBufferedBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "streamCipher_", "LLibOrgBouncycastleCryptoStreamCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "aeadBlockCipher_", "LLibOrgBouncycastleCryptoModesAEADBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "buf_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "markBuf_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "bufOff_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "maxBuf_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "finalized_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "markPosition_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "markBufOff_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoInputStream;LLibOrgBouncycastleCryptoBufferedBlockCipher;", "LJavaIoInputStream;LLibOrgBouncycastleCryptoStreamCipher;", "LJavaIoInputStream;LLibOrgBouncycastleCryptoModesAEADBlockCipher;", "LJavaIoInputStream;LLibOrgBouncycastleCryptoBufferedBlockCipher;I", "LJavaIoInputStream;LLibOrgBouncycastleCryptoStreamCipher;I", "LJavaIoInputStream;LLibOrgBouncycastleCryptoModesAEADBlockCipher;I", "LJavaIoIOException;", "read", "[B", "[BII", "skip", "J", "ensureCapacity", "IZ", "mark", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream = { "CryptoIoCipherInputStream", "lib.org.bouncycastle.crypto.io", ptrTable, methods, fields, 7, 0x1, 18, 13, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream;
}

@end

void LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoBufferedBlockCipher_(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *self, JavaIoInputStream *is, LibOrgBouncycastleCryptoBufferedBlockCipher *cipher) {
  LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoBufferedBlockCipher_withInt_(self, is, cipher, LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_INPUT_BUF_SIZE);
}

LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *new_LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoBufferedBlockCipher_(JavaIoInputStream *is, LibOrgBouncycastleCryptoBufferedBlockCipher *cipher) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoBufferedBlockCipher_, is, cipher)
}

LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *create_LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoBufferedBlockCipher_(JavaIoInputStream *is, LibOrgBouncycastleCryptoBufferedBlockCipher *cipher) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoBufferedBlockCipher_, is, cipher)
}

void LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoStreamCipher_(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *self, JavaIoInputStream *is, id<LibOrgBouncycastleCryptoStreamCipher> cipher) {
  LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoStreamCipher_withInt_(self, is, cipher, LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_INPUT_BUF_SIZE);
}

LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *new_LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoStreamCipher_(JavaIoInputStream *is, id<LibOrgBouncycastleCryptoStreamCipher> cipher) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoStreamCipher_, is, cipher)
}

LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *create_LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoStreamCipher_(JavaIoInputStream *is, id<LibOrgBouncycastleCryptoStreamCipher> cipher) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoStreamCipher_, is, cipher)
}

void LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoModesAEADBlockCipher_(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *self, JavaIoInputStream *is, id<LibOrgBouncycastleCryptoModesAEADBlockCipher> cipher) {
  LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withInt_(self, is, cipher, LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_INPUT_BUF_SIZE);
}

LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *new_LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoModesAEADBlockCipher_(JavaIoInputStream *is, id<LibOrgBouncycastleCryptoModesAEADBlockCipher> cipher) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoModesAEADBlockCipher_, is, cipher)
}

LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *create_LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoModesAEADBlockCipher_(JavaIoInputStream *is, id<LibOrgBouncycastleCryptoModesAEADBlockCipher> cipher) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoModesAEADBlockCipher_, is, cipher)
}

void LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoBufferedBlockCipher_withInt_(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *self, JavaIoInputStream *is, LibOrgBouncycastleCryptoBufferedBlockCipher *cipher, jint bufSize) {
  JavaIoFilterInputStream_initWithJavaIoInputStream_(self, is);
  self->bufferedBlockCipher_ = cipher;
  self->inBuf_ = [IOSByteArray newArrayWithLength:bufSize];
  self->skippingCipher_ = ([LibOrgBouncycastleCryptoSkippingCipher_class_() isInstance:cipher]) ? (id<LibOrgBouncycastleCryptoSkippingCipher>) cast_check(cipher, LibOrgBouncycastleCryptoSkippingCipher_class_()) : nil;
}

LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *new_LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoBufferedBlockCipher_withInt_(JavaIoInputStream *is, LibOrgBouncycastleCryptoBufferedBlockCipher *cipher, jint bufSize) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoBufferedBlockCipher_withInt_, is, cipher, bufSize)
}

LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *create_LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoBufferedBlockCipher_withInt_(JavaIoInputStream *is, LibOrgBouncycastleCryptoBufferedBlockCipher *cipher, jint bufSize) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoBufferedBlockCipher_withInt_, is, cipher, bufSize)
}

void LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoStreamCipher_withInt_(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *self, JavaIoInputStream *is, id<LibOrgBouncycastleCryptoStreamCipher> cipher, jint bufSize) {
  JavaIoFilterInputStream_initWithJavaIoInputStream_(self, is);
  self->streamCipher_ = cipher;
  self->inBuf_ = [IOSByteArray newArrayWithLength:bufSize];
  self->skippingCipher_ = ([LibOrgBouncycastleCryptoSkippingCipher_class_() isInstance:cipher]) ? (id<LibOrgBouncycastleCryptoSkippingCipher>) cast_check(cipher, LibOrgBouncycastleCryptoSkippingCipher_class_()) : nil;
}

LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *new_LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoStreamCipher_withInt_(JavaIoInputStream *is, id<LibOrgBouncycastleCryptoStreamCipher> cipher, jint bufSize) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoStreamCipher_withInt_, is, cipher, bufSize)
}

LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *create_LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoStreamCipher_withInt_(JavaIoInputStream *is, id<LibOrgBouncycastleCryptoStreamCipher> cipher, jint bufSize) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoStreamCipher_withInt_, is, cipher, bufSize)
}

void LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withInt_(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *self, JavaIoInputStream *is, id<LibOrgBouncycastleCryptoModesAEADBlockCipher> cipher, jint bufSize) {
  JavaIoFilterInputStream_initWithJavaIoInputStream_(self, is);
  self->aeadBlockCipher_ = cipher;
  self->inBuf_ = [IOSByteArray newArrayWithLength:bufSize];
  self->skippingCipher_ = ([LibOrgBouncycastleCryptoSkippingCipher_class_() isInstance:cipher]) ? (id<LibOrgBouncycastleCryptoSkippingCipher>) cast_check(cipher, LibOrgBouncycastleCryptoSkippingCipher_class_()) : nil;
}

LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *new_LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withInt_(JavaIoInputStream *is, id<LibOrgBouncycastleCryptoModesAEADBlockCipher> cipher, jint bufSize) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withInt_, is, cipher, bufSize)
}

LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *create_LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withInt_(JavaIoInputStream *is, id<LibOrgBouncycastleCryptoModesAEADBlockCipher> cipher, jint bufSize) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withInt_, is, cipher, bufSize)
}

jint LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_nextChunk(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *self) {
  if (self->finalized_) {
    return -1;
  }
  self->bufOff_ = 0;
  self->maxBuf_ = 0;
  while (self->maxBuf_ == 0) {
    jint read = [((JavaIoInputStream *) nil_chk(JreLoadVolatileId(&self->in_))) readWithByteArray:self->inBuf_];
    if (read == -1) {
      LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_finaliseCipher(self);
      if (self->maxBuf_ == 0) {
        return -1;
      }
      return self->maxBuf_;
    }
    @try {
      LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_ensureCapacityWithInt_withBoolean_(self, read, false);
      if (self->bufferedBlockCipher_ != nil) {
        self->maxBuf_ = [self->bufferedBlockCipher_ processBytesWithByteArray:self->inBuf_ withInt:0 withInt:read withByteArray:self->buf_ withInt:0];
      }
      else if (self->aeadBlockCipher_ != nil) {
        self->maxBuf_ = [self->aeadBlockCipher_ processBytesWithByteArray:self->inBuf_ withInt:0 withInt:read withByteArray:self->buf_ withInt:0];
      }
      else {
        [((id<LibOrgBouncycastleCryptoStreamCipher>) nil_chk(self->streamCipher_)) processBytesWithByteArray:self->inBuf_ withInt:0 withInt:read withByteArray:self->buf_ withInt:0];
        self->maxBuf_ = read;
      }
    }
    @catch (JavaLangException *e) {
      @throw new_LibOrgBouncycastleCryptoIoCipherIOException_initWithNSString_withJavaLangThrowable_(@"Error processing stream ", e);
    }
  }
  return self->maxBuf_;
}

void LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_finaliseCipher(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *self) {
  @try {
    self->finalized_ = true;
    LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_ensureCapacityWithInt_withBoolean_(self, 0, true);
    if (self->bufferedBlockCipher_ != nil) {
      self->maxBuf_ = [self->bufferedBlockCipher_ doFinalWithByteArray:self->buf_ withInt:0];
    }
    else if (self->aeadBlockCipher_ != nil) {
      self->maxBuf_ = [self->aeadBlockCipher_ doFinalWithByteArray:self->buf_ withInt:0];
    }
    else {
      self->maxBuf_ = 0;
    }
  }
  @catch (LibOrgBouncycastleCryptoInvalidCipherTextException *e) {
    @throw new_LibOrgBouncycastleCryptoIoInvalidCipherTextIOException_initWithNSString_withJavaLangThrowable_(@"Error finalising cipher", e);
  }
  @catch (JavaLangException *e) {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$@", @"Error finalising cipher ", e));
  }
}

void LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream_ensureCapacityWithInt_withBoolean_(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream *self, jint updateSize, jboolean finalOutput) {
  jint bufLen = updateSize;
  if (finalOutput) {
    if (self->bufferedBlockCipher_ != nil) {
      bufLen = [self->bufferedBlockCipher_ getOutputSizeWithInt:updateSize];
    }
    else if (self->aeadBlockCipher_ != nil) {
      bufLen = [self->aeadBlockCipher_ getOutputSizeWithInt:updateSize];
    }
  }
  else {
    if (self->bufferedBlockCipher_ != nil) {
      bufLen = [self->bufferedBlockCipher_ getUpdateOutputSizeWithInt:updateSize];
    }
    else if (self->aeadBlockCipher_ != nil) {
      bufLen = [self->aeadBlockCipher_ getUpdateOutputSizeWithInt:updateSize];
    }
  }
  if ((self->buf_ == nil) || (((IOSByteArray *) nil_chk(self->buf_))->size_ < bufLen)) {
    self->buf_ = [IOSByteArray newArrayWithLength:bufLen];
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoIoCryptoIoCipherInputStream)