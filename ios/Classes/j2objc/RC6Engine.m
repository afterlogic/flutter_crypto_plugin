//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/RC6Engine.java
//

#include "CipherParameters.h"
#include "DataLengthException.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "OutputLengthException.h"
#include "RC6Engine.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"

@interface LibOrgBouncycastleCryptoEnginesRC6Engine () {
 @public
  IOSIntArray *_S_;
  jboolean forEncryption_;
}

- (void)setKeyWithByteArray:(IOSByteArray *)key;

- (jint)encryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (jint)decryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (jint)rotateLeftWithInt:(jint)x
                  withInt:(jint)y;

- (jint)rotateRightWithInt:(jint)x
                   withInt:(jint)y;

- (jint)bytesToWordWithByteArray:(IOSByteArray *)src
                         withInt:(jint)srcOff;

- (void)wordToBytesWithInt:(jint)word
             withByteArray:(IOSByteArray *)dst
                   withInt:(jint)dstOff;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesRC6Engine, _S_, IOSIntArray *)

inline jint LibOrgBouncycastleCryptoEnginesRC6Engine_get_wordSize(void);
#define LibOrgBouncycastleCryptoEnginesRC6Engine_wordSize 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesRC6Engine, wordSize, jint)

inline jint LibOrgBouncycastleCryptoEnginesRC6Engine_get_bytesPerWord(void);
#define LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesRC6Engine, bytesPerWord, jint)

inline jint LibOrgBouncycastleCryptoEnginesRC6Engine_get__noRounds(void);
#define LibOrgBouncycastleCryptoEnginesRC6Engine__noRounds 20
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesRC6Engine, _noRounds, jint)

inline jint LibOrgBouncycastleCryptoEnginesRC6Engine_get_P32(void);
#define LibOrgBouncycastleCryptoEnginesRC6Engine_P32 -1209970333
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesRC6Engine, P32, jint)

inline jint LibOrgBouncycastleCryptoEnginesRC6Engine_get_Q32(void);
#define LibOrgBouncycastleCryptoEnginesRC6Engine_Q32 -1640531527
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesRC6Engine, Q32, jint)

inline jint LibOrgBouncycastleCryptoEnginesRC6Engine_get_LGW(void);
#define LibOrgBouncycastleCryptoEnginesRC6Engine_LGW 5
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesRC6Engine, LGW, jint)

__attribute__((unused)) static void LibOrgBouncycastleCryptoEnginesRC6Engine_setKeyWithByteArray_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, IOSByteArray *key);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesRC6Engine_encryptBlockWithByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesRC6Engine_decryptBlockWithByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesRC6Engine_rotateLeftWithInt_withInt_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, jint x, jint y);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesRC6Engine_rotateRightWithInt_withInt_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, jint x, jint y);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesRC6Engine_bytesToWordWithByteArray_withInt_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, IOSByteArray *src, jint srcOff);

__attribute__((unused)) static void LibOrgBouncycastleCryptoEnginesRC6Engine_wordToBytesWithInt_withByteArray_withInt_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, jint word, IOSByteArray *dst, jint dstOff);

@implementation LibOrgBouncycastleCryptoEnginesRC6Engine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoEnginesRC6Engine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (NSString *)getAlgorithmName {
  return @"RC6";
}

- (jint)getBlockSize {
  return 4 * LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord;
}

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  if (!([params isKindOfClass:[LibOrgBouncycastleCryptoParamsKeyParameter class]])) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"invalid parameter passed to RC6 init - ", [[((id<LibOrgBouncycastleCryptoCipherParameters>) nil_chk(params)) java_getClass] getName]));
  }
  LibOrgBouncycastleCryptoParamsKeyParameter *p = (LibOrgBouncycastleCryptoParamsKeyParameter *) cast_chk(params, [LibOrgBouncycastleCryptoParamsKeyParameter class]);
  self->forEncryption_ = forEncryption;
  LibOrgBouncycastleCryptoEnginesRC6Engine_setKeyWithByteArray_(self, [((LibOrgBouncycastleCryptoParamsKeyParameter *) nil_chk(p)) getKey]);
}

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  jint blockSize = [self getBlockSize];
  if (_S_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"RC6 engine not initialised");
  }
  if ((inOff + blockSize) > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if ((outOff + blockSize) > ((IOSByteArray *) nil_chk(outArg))->size_) {
    @throw new_LibOrgBouncycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  return (forEncryption_) ? LibOrgBouncycastleCryptoEnginesRC6Engine_encryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff) : LibOrgBouncycastleCryptoEnginesRC6Engine_decryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff);
}

- (void)reset {
}

- (void)setKeyWithByteArray:(IOSByteArray *)key {
  LibOrgBouncycastleCryptoEnginesRC6Engine_setKeyWithByteArray_(self, key);
}

- (jint)encryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  return LibOrgBouncycastleCryptoEnginesRC6Engine_encryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff);
}

- (jint)decryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  return LibOrgBouncycastleCryptoEnginesRC6Engine_decryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff);
}

- (jint)rotateLeftWithInt:(jint)x
                  withInt:(jint)y {
  return LibOrgBouncycastleCryptoEnginesRC6Engine_rotateLeftWithInt_withInt_(self, x, y);
}

- (jint)rotateRightWithInt:(jint)x
                   withInt:(jint)y {
  return LibOrgBouncycastleCryptoEnginesRC6Engine_rotateRightWithInt_withInt_(self, x, y);
}

- (jint)bytesToWordWithByteArray:(IOSByteArray *)src
                         withInt:(jint)srcOff {
  return LibOrgBouncycastleCryptoEnginesRC6Engine_bytesToWordWithByteArray_withInt_(self, src, srcOff);
}

- (void)wordToBytesWithInt:(jint)word
             withByteArray:(IOSByteArray *)dst
                   withInt:(jint)dstOff {
  LibOrgBouncycastleCryptoEnginesRC6Engine_wordToBytesWithInt_withByteArray_withInt_(self, word, dst, dstOff);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 4, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 6, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 7, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 8, 9, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 10, 9, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 11, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 13, 14, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getAlgorithmName);
  methods[2].selector = @selector(getBlockSize);
  methods[3].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[4].selector = @selector(processBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[5].selector = @selector(reset);
  methods[6].selector = @selector(setKeyWithByteArray:);
  methods[7].selector = @selector(encryptBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[8].selector = @selector(decryptBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[9].selector = @selector(rotateLeftWithInt:withInt:);
  methods[10].selector = @selector(rotateRightWithInt:withInt:);
  methods[11].selector = @selector(bytesToWordWithByteArray:withInt:);
  methods[12].selector = @selector(wordToBytesWithInt:withByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "wordSize", "I", .constantValue.asInt = LibOrgBouncycastleCryptoEnginesRC6Engine_wordSize, 0x1a, -1, -1, -1, -1 },
    { "bytesPerWord", "I", .constantValue.asInt = LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord, 0x1a, -1, -1, -1, -1 },
    { "_noRounds", "I", .constantValue.asInt = LibOrgBouncycastleCryptoEnginesRC6Engine__noRounds, 0x1a, -1, -1, -1, -1 },
    { "_S_", "[I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "P32", "I", .constantValue.asInt = LibOrgBouncycastleCryptoEnginesRC6Engine_P32, 0x1a, -1, -1, -1, -1 },
    { "Q32", "I", .constantValue.asInt = LibOrgBouncycastleCryptoEnginesRC6Engine_Q32, 0x1a, -1, -1, -1, -1 },
    { "LGW", "I", .constantValue.asInt = LibOrgBouncycastleCryptoEnginesRC6Engine_LGW, 0x1a, -1, -1, -1, -1 },
    { "forEncryption_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "processBlock", "[BI[BI", "setKey", "[B", "encryptBlock", "decryptBlock", "rotateLeft", "II", "rotateRight", "bytesToWord", "[BI", "wordToBytes", "I[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesRC6Engine = { "RC6Engine", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 13, 8, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesRC6Engine;
}

@end

void LibOrgBouncycastleCryptoEnginesRC6Engine_init(LibOrgBouncycastleCryptoEnginesRC6Engine *self) {
  NSObject_init(self);
  self->_S_ = nil;
}

LibOrgBouncycastleCryptoEnginesRC6Engine *new_LibOrgBouncycastleCryptoEnginesRC6Engine_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesRC6Engine, init)
}

LibOrgBouncycastleCryptoEnginesRC6Engine *create_LibOrgBouncycastleCryptoEnginesRC6Engine_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesRC6Engine, init)
}

void LibOrgBouncycastleCryptoEnginesRC6Engine_setKeyWithByteArray_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, IOSByteArray *key) {
  jint c = (((IOSByteArray *) nil_chk(key))->size_ + (LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord - 1)) / LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord;
  if (c == 0) {
    c = 1;
  }
  IOSIntArray *L = [IOSIntArray newArrayWithLength:(key->size_ + LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord - 1) / LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord];
  for (jint i = key->size_ - 1; i >= 0; i--) {
    *IOSIntArray_GetRef(L, i / LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord) = (JreLShift32(IOSIntArray_Get(L, i / LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord), 8)) + (IOSByteArray_Get(key, i) & (jint) 0xff);
  }
  self->_S_ = [IOSIntArray newArrayWithLength:2 + 2 * LibOrgBouncycastleCryptoEnginesRC6Engine__noRounds + 2];
  *IOSIntArray_GetRef(self->_S_, 0) = LibOrgBouncycastleCryptoEnginesRC6Engine_P32;
  for (jint i = 1; i < self->_S_->size_; i++) {
    *IOSIntArray_GetRef(self->_S_, i) = (IOSIntArray_Get(self->_S_, i - 1) + LibOrgBouncycastleCryptoEnginesRC6Engine_Q32);
  }
  jint iter;
  if (L->size_ > self->_S_->size_) {
    iter = 3 * L->size_;
  }
  else {
    iter = 3 * self->_S_->size_;
  }
  jint A = 0;
  jint B = 0;
  jint i = 0;
  jint j = 0;
  for (jint k = 0; k < iter; k++) {
    A = *IOSIntArray_GetRef(self->_S_, i) = LibOrgBouncycastleCryptoEnginesRC6Engine_rotateLeftWithInt_withInt_(self, IOSIntArray_Get(self->_S_, i) + A + B, 3);
    B = *IOSIntArray_GetRef(L, j) = LibOrgBouncycastleCryptoEnginesRC6Engine_rotateLeftWithInt_withInt_(self, IOSIntArray_Get(L, j) + A + B, A + B);
    i = (i + 1) % ((IOSIntArray *) nil_chk(self->_S_))->size_;
    j = (j + 1) % L->size_;
  }
}

jint LibOrgBouncycastleCryptoEnginesRC6Engine_encryptBlockWithByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff) {
  jint A = LibOrgBouncycastleCryptoEnginesRC6Engine_bytesToWordWithByteArray_withInt_(self, inArg, inOff);
  jint B = LibOrgBouncycastleCryptoEnginesRC6Engine_bytesToWordWithByteArray_withInt_(self, inArg, inOff + LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord);
  jint C = LibOrgBouncycastleCryptoEnginesRC6Engine_bytesToWordWithByteArray_withInt_(self, inArg, inOff + LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord * 2);
  jint D = LibOrgBouncycastleCryptoEnginesRC6Engine_bytesToWordWithByteArray_withInt_(self, inArg, inOff + LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord * 3);
  B += IOSIntArray_Get(nil_chk(self->_S_), 0);
  D += IOSIntArray_Get(self->_S_, 1);
  for (jint i = 1; i <= LibOrgBouncycastleCryptoEnginesRC6Engine__noRounds; i++) {
    jint t = 0;
    jint u = 0;
    t = B * (2 * B + 1);
    t = LibOrgBouncycastleCryptoEnginesRC6Engine_rotateLeftWithInt_withInt_(self, t, 5);
    u = D * (2 * D + 1);
    u = LibOrgBouncycastleCryptoEnginesRC6Engine_rotateLeftWithInt_withInt_(self, u, 5);
    A ^= t;
    A = LibOrgBouncycastleCryptoEnginesRC6Engine_rotateLeftWithInt_withInt_(self, A, u);
    A += IOSIntArray_Get(nil_chk(self->_S_), 2 * i);
    C ^= u;
    C = LibOrgBouncycastleCryptoEnginesRC6Engine_rotateLeftWithInt_withInt_(self, C, t);
    C += IOSIntArray_Get(nil_chk(self->_S_), 2 * i + 1);
    jint temp = A;
    A = B;
    B = C;
    C = D;
    D = temp;
  }
  A += IOSIntArray_Get(self->_S_, 2 * LibOrgBouncycastleCryptoEnginesRC6Engine__noRounds + 2);
  C += IOSIntArray_Get(self->_S_, 2 * LibOrgBouncycastleCryptoEnginesRC6Engine__noRounds + 3);
  LibOrgBouncycastleCryptoEnginesRC6Engine_wordToBytesWithInt_withByteArray_withInt_(self, A, outArg, outOff);
  LibOrgBouncycastleCryptoEnginesRC6Engine_wordToBytesWithInt_withByteArray_withInt_(self, B, outArg, outOff + LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord);
  LibOrgBouncycastleCryptoEnginesRC6Engine_wordToBytesWithInt_withByteArray_withInt_(self, C, outArg, outOff + LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord * 2);
  LibOrgBouncycastleCryptoEnginesRC6Engine_wordToBytesWithInt_withByteArray_withInt_(self, D, outArg, outOff + LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord * 3);
  return 4 * LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord;
}

jint LibOrgBouncycastleCryptoEnginesRC6Engine_decryptBlockWithByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff) {
  jint A = LibOrgBouncycastleCryptoEnginesRC6Engine_bytesToWordWithByteArray_withInt_(self, inArg, inOff);
  jint B = LibOrgBouncycastleCryptoEnginesRC6Engine_bytesToWordWithByteArray_withInt_(self, inArg, inOff + LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord);
  jint C = LibOrgBouncycastleCryptoEnginesRC6Engine_bytesToWordWithByteArray_withInt_(self, inArg, inOff + LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord * 2);
  jint D = LibOrgBouncycastleCryptoEnginesRC6Engine_bytesToWordWithByteArray_withInt_(self, inArg, inOff + LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord * 3);
  C -= IOSIntArray_Get(nil_chk(self->_S_), 2 * LibOrgBouncycastleCryptoEnginesRC6Engine__noRounds + 3);
  A -= IOSIntArray_Get(self->_S_, 2 * LibOrgBouncycastleCryptoEnginesRC6Engine__noRounds + 2);
  for (jint i = LibOrgBouncycastleCryptoEnginesRC6Engine__noRounds; i >= 1; i--) {
    jint t = 0;
    jint u = 0;
    jint temp = D;
    D = C;
    C = B;
    B = A;
    A = temp;
    t = B * (2 * B + 1);
    t = LibOrgBouncycastleCryptoEnginesRC6Engine_rotateLeftWithInt_withInt_(self, t, LibOrgBouncycastleCryptoEnginesRC6Engine_LGW);
    u = D * (2 * D + 1);
    u = LibOrgBouncycastleCryptoEnginesRC6Engine_rotateLeftWithInt_withInt_(self, u, LibOrgBouncycastleCryptoEnginesRC6Engine_LGW);
    C -= IOSIntArray_Get(nil_chk(self->_S_), 2 * i + 1);
    C = LibOrgBouncycastleCryptoEnginesRC6Engine_rotateRightWithInt_withInt_(self, C, t);
    C ^= u;
    A -= IOSIntArray_Get(nil_chk(self->_S_), 2 * i);
    A = LibOrgBouncycastleCryptoEnginesRC6Engine_rotateRightWithInt_withInt_(self, A, u);
    A ^= t;
  }
  D -= IOSIntArray_Get(nil_chk(self->_S_), 1);
  B -= IOSIntArray_Get(self->_S_, 0);
  LibOrgBouncycastleCryptoEnginesRC6Engine_wordToBytesWithInt_withByteArray_withInt_(self, A, outArg, outOff);
  LibOrgBouncycastleCryptoEnginesRC6Engine_wordToBytesWithInt_withByteArray_withInt_(self, B, outArg, outOff + LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord);
  LibOrgBouncycastleCryptoEnginesRC6Engine_wordToBytesWithInt_withByteArray_withInt_(self, C, outArg, outOff + LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord * 2);
  LibOrgBouncycastleCryptoEnginesRC6Engine_wordToBytesWithInt_withByteArray_withInt_(self, D, outArg, outOff + LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord * 3);
  return 4 * LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord;
}

jint LibOrgBouncycastleCryptoEnginesRC6Engine_rotateLeftWithInt_withInt_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, jint x, jint y) {
  return (JreLShift32(x, y)) | (JreURShift32(x, -y));
}

jint LibOrgBouncycastleCryptoEnginesRC6Engine_rotateRightWithInt_withInt_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, jint x, jint y) {
  return (JreURShift32(x, y)) | (JreLShift32(x, -y));
}

jint LibOrgBouncycastleCryptoEnginesRC6Engine_bytesToWordWithByteArray_withInt_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, IOSByteArray *src, jint srcOff) {
  jint word = 0;
  for (jint i = LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord - 1; i >= 0; i--) {
    word = (JreLShift32(word, 8)) + (IOSByteArray_Get(nil_chk(src), i + srcOff) & (jint) 0xff);
  }
  return word;
}

void LibOrgBouncycastleCryptoEnginesRC6Engine_wordToBytesWithInt_withByteArray_withInt_(LibOrgBouncycastleCryptoEnginesRC6Engine *self, jint word, IOSByteArray *dst, jint dstOff) {
  for (jint i = 0; i < LibOrgBouncycastleCryptoEnginesRC6Engine_bytesPerWord; i++) {
    *IOSByteArray_GetRef(nil_chk(dst), i + dstOff) = (jbyte) word;
    JreURShiftAssignInt(&word, 8);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesRC6Engine)