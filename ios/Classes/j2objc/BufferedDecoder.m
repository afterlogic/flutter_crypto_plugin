//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/encoders/BufferedDecoder.java
//

#include "BufferedDecoder.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Translator.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"

@implementation LibOrgBouncycastleUtilEncodersBufferedDecoder

- (instancetype)initWithLibOrgBouncycastleUtilEncodersTranslator:(id<LibOrgBouncycastleUtilEncodersTranslator>)translator
                                                         withInt:(jint)bufSize {
  LibOrgBouncycastleUtilEncodersBufferedDecoder_initWithLibOrgBouncycastleUtilEncodersTranslator_withInt_(self, translator, bufSize);
  return self;
}

- (jint)processByteWithByte:(jbyte)inArg
              withByteArray:(IOSByteArray *)outArg
                    withInt:(jint)outOff {
  jint resultLen = 0;
  *IOSByteArray_GetRef(nil_chk(buf_), bufOff_++) = inArg;
  if (bufOff_ == buf_->size_) {
    resultLen = [((id<LibOrgBouncycastleUtilEncodersTranslator>) nil_chk(translator_)) decodeWithByteArray:buf_ withInt:0 withInt:buf_->size_ withByteArray:outArg withInt:outOff];
    bufOff_ = 0;
  }
  return resultLen;
}

- (jint)processBytesWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                          withInt:(jint)len
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  if (len < 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Can't have a negative input length!");
  }
  jint resultLen = 0;
  jint gapLen = ((IOSByteArray *) nil_chk(buf_))->size_ - bufOff_;
  if (len > gapLen) {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, buf_, bufOff_, gapLen);
    resultLen += [((id<LibOrgBouncycastleUtilEncodersTranslator>) nil_chk(translator_)) decodeWithByteArray:buf_ withInt:0 withInt:((IOSByteArray *) nil_chk(buf_))->size_ withByteArray:outArg withInt:outOff];
    bufOff_ = 0;
    len -= gapLen;
    inOff += gapLen;
    outOff += resultLen;
    jint chunkSize = len - (len % ((IOSByteArray *) nil_chk(buf_))->size_);
    resultLen += [((id<LibOrgBouncycastleUtilEncodersTranslator>) nil_chk(translator_)) decodeWithByteArray:inArg withInt:inOff withInt:chunkSize withByteArray:outArg withInt:outOff];
    len -= chunkSize;
    inOff += chunkSize;
  }
  if (len != 0) {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, buf_, bufOff_, len);
    bufOff_ += len;
  }
  return resultLen;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleUtilEncodersTranslator:withInt:);
  methods[1].selector = @selector(processByteWithByte:withByteArray:withInt:);
  methods[2].selector = @selector(processBytesWithByteArray:withInt:withInt:withByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "buf_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "bufOff_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "translator_", "LLibOrgBouncycastleUtilEncodersTranslator;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleUtilEncodersTranslator;I", "processByte", "B[BI", "processBytes", "[BII[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilEncodersBufferedDecoder = { "BufferedDecoder", "lib.org.bouncycastle.util.encoders", ptrTable, methods, fields, 7, 0x1, 3, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilEncodersBufferedDecoder;
}

@end

void LibOrgBouncycastleUtilEncodersBufferedDecoder_initWithLibOrgBouncycastleUtilEncodersTranslator_withInt_(LibOrgBouncycastleUtilEncodersBufferedDecoder *self, id<LibOrgBouncycastleUtilEncodersTranslator> translator, jint bufSize) {
  NSObject_init(self);
  self->translator_ = translator;
  if ((bufSize % [((id<LibOrgBouncycastleUtilEncodersTranslator>) nil_chk(translator)) getEncodedBlockSize]) != 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"buffer size not multiple of input block size");
  }
  self->buf_ = [IOSByteArray newArrayWithLength:bufSize];
  self->bufOff_ = 0;
}

LibOrgBouncycastleUtilEncodersBufferedDecoder *new_LibOrgBouncycastleUtilEncodersBufferedDecoder_initWithLibOrgBouncycastleUtilEncodersTranslator_withInt_(id<LibOrgBouncycastleUtilEncodersTranslator> translator, jint bufSize) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilEncodersBufferedDecoder, initWithLibOrgBouncycastleUtilEncodersTranslator_withInt_, translator, bufSize)
}

LibOrgBouncycastleUtilEncodersBufferedDecoder *create_LibOrgBouncycastleUtilEncodersBufferedDecoder_initWithLibOrgBouncycastleUtilEncodersTranslator_withInt_(id<LibOrgBouncycastleUtilEncodersTranslator> translator, jint bufSize) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilEncodersBufferedDecoder, initWithLibOrgBouncycastleUtilEncodersTranslator_withInt_, translator, bufSize)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilEncodersBufferedDecoder)
