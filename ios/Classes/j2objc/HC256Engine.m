//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/HC256Engine.java
//

#include "CipherParameters.h"
#include "DataLengthException.h"
#include "HC256Engine.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "OutputLengthException.h"
#include "ParametersWithIV.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoEnginesHC256Engine () {
 @public
  IOSIntArray *p_;
  IOSIntArray *q_;
  jint cnt_;
  IOSByteArray *key_;
  IOSByteArray *iv_;
  jboolean initialised_;
  IOSByteArray *buf_;
  jint idx_;
}

- (jint)step;

- (void)init__ OBJC_METHOD_FAMILY_NONE;

- (jbyte)getByte;

+ (jint)rotateRightWithInt:(jint)x
                   withInt:(jint)bits;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesHC256Engine, p_, IOSIntArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesHC256Engine, q_, IOSIntArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesHC256Engine, key_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesHC256Engine, iv_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesHC256Engine, buf_, IOSByteArray *)

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesHC256Engine_step(LibOrgBouncycastleCryptoEnginesHC256Engine *self);

__attribute__((unused)) static void LibOrgBouncycastleCryptoEnginesHC256Engine_init__(LibOrgBouncycastleCryptoEnginesHC256Engine *self);

__attribute__((unused)) static jbyte LibOrgBouncycastleCryptoEnginesHC256Engine_getByte(LibOrgBouncycastleCryptoEnginesHC256Engine *self);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesHC256Engine_rotateRightWithInt_withInt_(jint x, jint bits);

@implementation LibOrgBouncycastleCryptoEnginesHC256Engine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoEnginesHC256Engine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jint)step {
  return LibOrgBouncycastleCryptoEnginesHC256Engine_step(self);
}

- (void)init__ {
  LibOrgBouncycastleCryptoEnginesHC256Engine_init__(self);
}

- (NSString *)getAlgorithmName {
  return @"HC-256";
}

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  id<LibOrgBouncycastleCryptoCipherParameters> keyParam = params;
  if ([params isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithIV class]]) {
    iv_ = [((LibOrgBouncycastleCryptoParamsParametersWithIV *) nil_chk(((LibOrgBouncycastleCryptoParamsParametersWithIV *) params))) getIV];
    keyParam = [((LibOrgBouncycastleCryptoParamsParametersWithIV *) nil_chk(((LibOrgBouncycastleCryptoParamsParametersWithIV *) params))) getParameters];
  }
  else {
    iv_ = [IOSByteArray newArrayWithLength:0];
  }
  if ([keyParam isKindOfClass:[LibOrgBouncycastleCryptoParamsKeyParameter class]]) {
    key_ = [((LibOrgBouncycastleCryptoParamsKeyParameter *) nil_chk(((LibOrgBouncycastleCryptoParamsKeyParameter *) keyParam))) getKey];
    LibOrgBouncycastleCryptoEnginesHC256Engine_init__(self);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid parameter passed to HC256 init - ", [[((id<LibOrgBouncycastleCryptoCipherParameters>) nil_chk(params)) java_getClass] getName]));
  }
  initialised_ = true;
}

- (jbyte)getByte {
  return LibOrgBouncycastleCryptoEnginesHC256Engine_getByte(self);
}

- (jint)processBytesWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                          withInt:(jint)len
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  if (!initialised_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", [self getAlgorithmName], @" not initialised"));
  }
  if ((inOff + len) > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if ((outOff + len) > ((IOSByteArray *) nil_chk(outArg))->size_) {
    @throw new_LibOrgBouncycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  for (jint i = 0; i < len; i++) {
    *IOSByteArray_GetRef(outArg, outOff + i) = (jbyte) (IOSByteArray_Get(inArg, inOff + i) ^ LibOrgBouncycastleCryptoEnginesHC256Engine_getByte(self));
  }
  return len;
}

- (void)reset {
  LibOrgBouncycastleCryptoEnginesHC256Engine_init__(self);
}

- (jbyte)returnByteWithByte:(jbyte)inArg {
  return (jbyte) (inArg ^ LibOrgBouncycastleCryptoEnginesHC256Engine_getByte(self));
}

+ (jint)rotateRightWithInt:(jint)x
                   withInt:(jint)bits {
  return LibOrgBouncycastleCryptoEnginesHC256Engine_rotateRightWithInt_withInt_(x, bits);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 0, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, 2, -1, -1, -1 },
    { NULL, "B", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, 4, 5, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "B", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "I", 0xa, 8, 9, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(step);
  methods[2].selector = @selector(init__);
  methods[3].selector = @selector(getAlgorithmName);
  methods[4].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[5].selector = @selector(getByte);
  methods[6].selector = @selector(processBytesWithByteArray:withInt:withInt:withByteArray:withInt:);
  methods[7].selector = @selector(reset);
  methods[8].selector = @selector(returnByteWithByte:);
  methods[9].selector = @selector(rotateRightWithInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "p_", "[I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "q_", "[I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cnt_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "key_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "iv_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "initialised_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "buf_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "idx_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "processBytes", "[BII[BI", "LLibOrgBouncycastleCryptoDataLengthException;", "returnByte", "B", "rotateRight", "II" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesHC256Engine = { "HC256Engine", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 10, 8, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesHC256Engine;
}

@end

void LibOrgBouncycastleCryptoEnginesHC256Engine_init(LibOrgBouncycastleCryptoEnginesHC256Engine *self) {
  NSObject_init(self);
  self->p_ = [IOSIntArray newArrayWithLength:1024];
  self->q_ = [IOSIntArray newArrayWithLength:1024];
  self->cnt_ = 0;
  self->buf_ = [IOSByteArray newArrayWithLength:4];
  self->idx_ = 0;
}

LibOrgBouncycastleCryptoEnginesHC256Engine *new_LibOrgBouncycastleCryptoEnginesHC256Engine_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesHC256Engine, init)
}

LibOrgBouncycastleCryptoEnginesHC256Engine *create_LibOrgBouncycastleCryptoEnginesHC256Engine_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesHC256Engine, init)
}

jint LibOrgBouncycastleCryptoEnginesHC256Engine_step(LibOrgBouncycastleCryptoEnginesHC256Engine *self) {
  jint j = self->cnt_ & (jint) 0x3FF;
  jint ret;
  if (self->cnt_ < 1024) {
    jint x = IOSIntArray_Get(nil_chk(self->p_), ((j - 3) & (jint) 0x3FF));
    jint y = IOSIntArray_Get(self->p_, ((j - 1023) & (jint) 0x3FF));
    *IOSIntArray_GetRef(self->p_, j) += IOSIntArray_Get(self->p_, ((j - 10) & (jint) 0x3FF)) + (LibOrgBouncycastleCryptoEnginesHC256Engine_rotateRightWithInt_withInt_(x, 10) ^ LibOrgBouncycastleCryptoEnginesHC256Engine_rotateRightWithInt_withInt_(y, 23)) + IOSIntArray_Get(nil_chk(self->q_), ((x ^ y) & (jint) 0x3FF));
    x = IOSIntArray_Get(nil_chk(self->p_), ((j - 12) & (jint) 0x3FF));
    ret = (IOSIntArray_Get(self->q_, x & (jint) 0xFF) + IOSIntArray_Get(self->q_, ((JreRShift32(x, 8)) & (jint) 0xFF) + 256) + IOSIntArray_Get(self->q_, ((JreRShift32(x, 16)) & (jint) 0xFF) + 512) + IOSIntArray_Get(self->q_, ((JreRShift32(x, 24)) & (jint) 0xFF) + 768)) ^ IOSIntArray_Get(self->p_, j);
  }
  else {
    jint x = IOSIntArray_Get(nil_chk(self->q_), ((j - 3) & (jint) 0x3FF));
    jint y = IOSIntArray_Get(self->q_, ((j - 1023) & (jint) 0x3FF));
    *IOSIntArray_GetRef(self->q_, j) += IOSIntArray_Get(self->q_, ((j - 10) & (jint) 0x3FF)) + (LibOrgBouncycastleCryptoEnginesHC256Engine_rotateRightWithInt_withInt_(x, 10) ^ LibOrgBouncycastleCryptoEnginesHC256Engine_rotateRightWithInt_withInt_(y, 23)) + IOSIntArray_Get(nil_chk(self->p_), ((x ^ y) & (jint) 0x3FF));
    x = IOSIntArray_Get(nil_chk(self->q_), ((j - 12) & (jint) 0x3FF));
    ret = (IOSIntArray_Get(self->p_, x & (jint) 0xFF) + IOSIntArray_Get(self->p_, ((JreRShift32(x, 8)) & (jint) 0xFF) + 256) + IOSIntArray_Get(self->p_, ((JreRShift32(x, 16)) & (jint) 0xFF) + 512) + IOSIntArray_Get(self->p_, ((JreRShift32(x, 24)) & (jint) 0xFF) + 768)) ^ IOSIntArray_Get(self->q_, j);
  }
  self->cnt_ = (self->cnt_ + 1) & (jint) 0x7FF;
  return ret;
}

void LibOrgBouncycastleCryptoEnginesHC256Engine_init__(LibOrgBouncycastleCryptoEnginesHC256Engine *self) {
  if (((IOSByteArray *) nil_chk(self->key_))->size_ != 32 && self->key_->size_ != 16) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"The key must be 128/256 bits long");
  }
  if (((IOSByteArray *) nil_chk(self->iv_))->size_ < 16) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"The IV must be at least 128 bits long");
  }
  if (self->key_->size_ != 32) {
    IOSByteArray *k = [IOSByteArray newArrayWithLength:32];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->key_, 0, k, 0, self->key_->size_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->key_, 0, k, 16, ((IOSByteArray *) nil_chk(self->key_))->size_);
    self->key_ = k;
  }
  if (((IOSByteArray *) nil_chk(self->iv_))->size_ < 32) {
    IOSByteArray *newIV = [IOSByteArray newArrayWithLength:32];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->iv_, 0, newIV, 0, self->iv_->size_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->iv_, 0, newIV, ((IOSByteArray *) nil_chk(self->iv_))->size_, newIV->size_ - self->iv_->size_);
    self->iv_ = newIV;
  }
  self->idx_ = 0;
  self->cnt_ = 0;
  IOSIntArray *w = [IOSIntArray newArrayWithLength:2560];
  for (jint i = 0; i < 32; i++) {
    *IOSIntArray_GetRef(w, JreRShift32(i, 2)) |= JreLShift32((IOSByteArray_Get(nil_chk(self->key_), i) & (jint) 0xff), (8 * (i & (jint) 0x3)));
  }
  for (jint i = 0; i < 32; i++) {
    *IOSIntArray_GetRef(w, (JreRShift32(i, 2)) + 8) |= JreLShift32((IOSByteArray_Get(self->iv_, i) & (jint) 0xff), (8 * (i & (jint) 0x3)));
  }
  for (jint i = 16; i < 2560; i++) {
    jint x = IOSIntArray_Get(w, i - 2);
    jint y = IOSIntArray_Get(w, i - 15);
    *IOSIntArray_GetRef(w, i) = (LibOrgBouncycastleCryptoEnginesHC256Engine_rotateRightWithInt_withInt_(x, 17) ^ LibOrgBouncycastleCryptoEnginesHC256Engine_rotateRightWithInt_withInt_(x, 19) ^ (JreURShift32(x, 10))) + IOSIntArray_Get(w, i - 7) + (LibOrgBouncycastleCryptoEnginesHC256Engine_rotateRightWithInt_withInt_(y, 7) ^ LibOrgBouncycastleCryptoEnginesHC256Engine_rotateRightWithInt_withInt_(y, 18) ^ (JreURShift32(y, 3))) + IOSIntArray_Get(w, i - 16) + i;
  }
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(w, 512, self->p_, 0, 1024);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(w, 1536, self->q_, 0, 1024);
  for (jint i = 0; i < 4096; i++) {
    LibOrgBouncycastleCryptoEnginesHC256Engine_step(self);
  }
  self->cnt_ = 0;
}

jbyte LibOrgBouncycastleCryptoEnginesHC256Engine_getByte(LibOrgBouncycastleCryptoEnginesHC256Engine *self) {
  if (self->idx_ == 0) {
    jint step = LibOrgBouncycastleCryptoEnginesHC256Engine_step(self);
    *IOSByteArray_GetRef(nil_chk(self->buf_), 0) = (jbyte) (step & (jint) 0xFF);
    JreRShiftAssignInt(&step, 8);
    *IOSByteArray_GetRef(self->buf_, 1) = (jbyte) (step & (jint) 0xFF);
    JreRShiftAssignInt(&step, 8);
    *IOSByteArray_GetRef(self->buf_, 2) = (jbyte) (step & (jint) 0xFF);
    JreRShiftAssignInt(&step, 8);
    *IOSByteArray_GetRef(self->buf_, 3) = (jbyte) (step & (jint) 0xFF);
  }
  jbyte ret = IOSByteArray_Get(nil_chk(self->buf_), self->idx_);
  self->idx_ = (self->idx_ + 1) & (jint) 0x3;
  return ret;
}

jint LibOrgBouncycastleCryptoEnginesHC256Engine_rotateRightWithInt_withInt_(jint x, jint bits) {
  LibOrgBouncycastleCryptoEnginesHC256Engine_initialize();
  return (JreURShift32(x, bits)) | (JreLShift32(x, -bits));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesHC256Engine)