//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/macs/SipHash.java
//

#include "CipherParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "Pack.h"
#include "SipHash.h"
#include "java/lang/IllegalArgumentException.h"

@implementation LibOrgBouncycastleCryptoMacsSipHash

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoMacsSipHash_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithInt:(jint)c
                    withInt:(jint)d {
  LibOrgBouncycastleCryptoMacsSipHash_initWithInt_withInt_(self, c, d);
  return self;
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$ICI", @"SipHash-", c_, '-', d_);
}

- (jint)getMacSize {
  return 8;
}

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  if (!([params isKindOfClass:[LibOrgBouncycastleCryptoParamsKeyParameter class]])) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'params' must be an instance of KeyParameter");
  }
  LibOrgBouncycastleCryptoParamsKeyParameter *keyParameter = (LibOrgBouncycastleCryptoParamsKeyParameter *) cast_chk(params, [LibOrgBouncycastleCryptoParamsKeyParameter class]);
  IOSByteArray *key = [((LibOrgBouncycastleCryptoParamsKeyParameter *) nil_chk(keyParameter)) getKey];
  if (((IOSByteArray *) nil_chk(key))->size_ != 16) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'params' must be a 128-bit key");
  }
  self->k0_ = LibOrgBouncycastleUtilPack_littleEndianToLongWithByteArray_withInt_(key, 0);
  self->k1_ = LibOrgBouncycastleUtilPack_littleEndianToLongWithByteArray_withInt_(key, 8);
  [self reset];
}

- (void)updateWithByte:(jbyte)input {
  JreURShiftAssignLong(&m_, 8);
  m_ |= JreLShift64((input & (jlong) 0xffLL), 56);
  if (++wordPos_ == 8) {
    [self processMessageWord];
    wordPos_ = 0;
  }
}

- (void)updateWithByteArray:(IOSByteArray *)input
                    withInt:(jint)offset
                    withInt:(jint)length {
  jint i = 0;
  jint fullWords = length & ~7;
  if (wordPos_ == 0) {
    for (; i < fullWords; i += 8) {
      m_ = LibOrgBouncycastleUtilPack_littleEndianToLongWithByteArray_withInt_(input, offset + i);
      [self processMessageWord];
    }
    for (; i < length; ++i) {
      JreURShiftAssignLong(&m_, 8);
      m_ |= JreLShift64((IOSByteArray_Get(nil_chk(input), offset + i) & (jlong) 0xffLL), 56);
    }
    wordPos_ = length - fullWords;
  }
  else {
    jint bits = JreLShift32(wordPos_, 3);
    for (; i < fullWords; i += 8) {
      jlong n = LibOrgBouncycastleUtilPack_littleEndianToLongWithByteArray_withInt_(input, offset + i);
      m_ = (JreLShift64(n, bits)) | (JreURShift64(m_, -bits));
      [self processMessageWord];
      m_ = n;
    }
    for (; i < length; ++i) {
      JreURShiftAssignLong(&m_, 8);
      m_ |= JreLShift64((IOSByteArray_Get(nil_chk(input), offset + i) & (jlong) 0xffLL), 56);
      if (++wordPos_ == 8) {
        [self processMessageWord];
        wordPos_ = 0;
      }
    }
  }
}

- (jlong)doFinal {
  JreURShiftAssignLong(&m_, (JreLShift32((7 - wordPos_), 3)));
  JreURShiftAssignLong(&m_, 8);
  m_ |= JreLShift64((((JreLShift32(wordCount_, 3)) + wordPos_) & (jlong) 0xffLL), 56);
  [self processMessageWord];
  v2_ ^= (jlong) 0xffLL;
  [self applySipRoundsWithInt:d_];
  jlong result = v0_ ^ v1_ ^ v2_ ^ v3_;
  [self reset];
  return result;
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  jlong result = [self doFinal];
  LibOrgBouncycastleUtilPack_longToLittleEndianWithLong_withByteArray_withInt_(result, outArg, outOff);
  return 8;
}

- (void)reset {
  v0_ = k0_ ^ (jlong) 0x736f6d6570736575LL;
  v1_ = k1_ ^ (jlong) 0x646f72616e646f6dLL;
  v2_ = k0_ ^ (jlong) 0x6c7967656e657261LL;
  v3_ = k1_ ^ (jlong) 0x7465646279746573LL;
  m_ = 0;
  wordPos_ = 0;
  wordCount_ = 0;
}

- (void)processMessageWord {
  ++wordCount_;
  v3_ ^= m_;
  [self applySipRoundsWithInt:c_];
  v0_ ^= m_;
}

- (void)applySipRoundsWithInt:(jint)n {
  jlong r0 = v0_;
  jlong r1 = v1_;
  jlong r2 = v2_;
  jlong r3 = v3_;
  for (jint r = 0; r < n; ++r) {
    r0 += r1;
    r2 += r3;
    r1 = LibOrgBouncycastleCryptoMacsSipHash_rotateLeftWithLong_withInt_(r1, 13);
    r3 = LibOrgBouncycastleCryptoMacsSipHash_rotateLeftWithLong_withInt_(r3, 16);
    r1 ^= r0;
    r3 ^= r2;
    r0 = LibOrgBouncycastleCryptoMacsSipHash_rotateLeftWithLong_withInt_(r0, 32);
    r2 += r1;
    r0 += r3;
    r1 = LibOrgBouncycastleCryptoMacsSipHash_rotateLeftWithLong_withInt_(r1, 17);
    r3 = LibOrgBouncycastleCryptoMacsSipHash_rotateLeftWithLong_withInt_(r3, 21);
    r1 ^= r2;
    r3 ^= r0;
    r2 = LibOrgBouncycastleCryptoMacsSipHash_rotateLeftWithLong_withInt_(r2, 32);
  }
  v0_ = r0;
  v1_ = r1;
  v2_ = r2;
  v3_ = r3;
}

+ (jlong)rotateLeftWithLong:(jlong)x
                    withInt:(jint)n {
  return LibOrgBouncycastleCryptoMacsSipHash_rotateLeftWithLong_withInt_(x, n);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, 6, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 7, 8, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, 8, -1, -1, -1 },
    { NULL, "I", 0x1, 9, 10, 8, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 11, 12, -1, -1, -1, -1 },
    { NULL, "J", 0xc, 13, 14, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithInt:withInt:);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(getMacSize);
  methods[4].selector = @selector(init__WithLibOrgBouncycastleCryptoCipherParameters:);
  methods[5].selector = @selector(updateWithByte:);
  methods[6].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[7].selector = @selector(doFinal);
  methods[8].selector = @selector(doFinalWithByteArray:withInt:);
  methods[9].selector = @selector(reset);
  methods[10].selector = @selector(processMessageWord);
  methods[11].selector = @selector(applySipRoundsWithInt:);
  methods[12].selector = @selector(rotateLeftWithLong:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "c_", "I", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
    { "d_", "I", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
    { "k0_", "J", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "k1_", "J", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "v0_", "J", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "v1_", "J", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "v2_", "J", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "v3_", "J", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "m_", "J", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "wordPos_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "wordCount_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "II", "init", "LLibOrgBouncycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "update", "B", "LJavaLangIllegalStateException;", "[BII", "LLibOrgBouncycastleCryptoDataLengthException;LJavaLangIllegalStateException;", "doFinal", "[BI", "applySipRounds", "I", "rotateLeft", "JI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoMacsSipHash = { "SipHash", "lib.org.bouncycastle.crypto.macs", ptrTable, methods, fields, 7, 0x1, 13, 11, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoMacsSipHash;
}

@end

void LibOrgBouncycastleCryptoMacsSipHash_init(LibOrgBouncycastleCryptoMacsSipHash *self) {
  NSObject_init(self);
  self->m_ = 0;
  self->wordPos_ = 0;
  self->wordCount_ = 0;
  self->c_ = 2;
  self->d_ = 4;
}

LibOrgBouncycastleCryptoMacsSipHash *new_LibOrgBouncycastleCryptoMacsSipHash_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoMacsSipHash, init)
}

LibOrgBouncycastleCryptoMacsSipHash *create_LibOrgBouncycastleCryptoMacsSipHash_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoMacsSipHash, init)
}

void LibOrgBouncycastleCryptoMacsSipHash_initWithInt_withInt_(LibOrgBouncycastleCryptoMacsSipHash *self, jint c, jint d) {
  NSObject_init(self);
  self->m_ = 0;
  self->wordPos_ = 0;
  self->wordCount_ = 0;
  self->c_ = c;
  self->d_ = d;
}

LibOrgBouncycastleCryptoMacsSipHash *new_LibOrgBouncycastleCryptoMacsSipHash_initWithInt_withInt_(jint c, jint d) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoMacsSipHash, initWithInt_withInt_, c, d)
}

LibOrgBouncycastleCryptoMacsSipHash *create_LibOrgBouncycastleCryptoMacsSipHash_initWithInt_withInt_(jint c, jint d) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoMacsSipHash, initWithInt_withInt_, c, d)
}

jlong LibOrgBouncycastleCryptoMacsSipHash_rotateLeftWithLong_withInt_(jlong x, jint n) {
  LibOrgBouncycastleCryptoMacsSipHash_initialize();
  return (JreLShift64(x, n)) | (JreURShift64(x, -n));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoMacsSipHash)
