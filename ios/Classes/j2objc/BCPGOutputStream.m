//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/BCPGOutputStream.java
//

#include "Arrays.h"
#include "BCPGObject.h"
#include "BCPGOutputStream.h"
#include "ContainedPacket.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/io/OutputStream.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleBcpgBCPGOutputStream () {
 @public
  IOSByteArray *partialBuffer_;
  jint partialBufferLength_;
  jint partialPower_;
  jint partialOffset_;
}

- (void)writeNewPacketLengthWithLong:(jlong)bodyLen;

- (void)writeHeaderWithInt:(jint)tag
               withBoolean:(jboolean)oldPackets
               withBoolean:(jboolean)partial
                  withLong:(jlong)bodyLen;

- (void)partialFlushWithBoolean:(jboolean)isLast;

- (void)writePartialWithByte:(jbyte)b;

- (void)writePartialWithByteArray:(IOSByteArray *)buf
                          withInt:(jint)off
                          withInt:(jint)len;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgBCPGOutputStream, partialBuffer_, IOSByteArray *)

inline jint LibOrgBouncycastleBcpgBCPGOutputStream_get_BUF_SIZE_POWER(void);
#define LibOrgBouncycastleBcpgBCPGOutputStream_BUF_SIZE_POWER 16
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleBcpgBCPGOutputStream, BUF_SIZE_POWER, jint)

__attribute__((unused)) static void LibOrgBouncycastleBcpgBCPGOutputStream_writeNewPacketLengthWithLong_(LibOrgBouncycastleBcpgBCPGOutputStream *self, jlong bodyLen);

__attribute__((unused)) static void LibOrgBouncycastleBcpgBCPGOutputStream_writeHeaderWithInt_withBoolean_withBoolean_withLong_(LibOrgBouncycastleBcpgBCPGOutputStream *self, jint tag, jboolean oldPackets, jboolean partial, jlong bodyLen);

__attribute__((unused)) static void LibOrgBouncycastleBcpgBCPGOutputStream_partialFlushWithBoolean_(LibOrgBouncycastleBcpgBCPGOutputStream *self, jboolean isLast);

__attribute__((unused)) static void LibOrgBouncycastleBcpgBCPGOutputStream_writePartialWithByte_(LibOrgBouncycastleBcpgBCPGOutputStream *self, jbyte b);

__attribute__((unused)) static void LibOrgBouncycastleBcpgBCPGOutputStream_writePartialWithByteArray_withInt_withInt_(LibOrgBouncycastleBcpgBCPGOutputStream *self, IOSByteArray *buf, jint off, jint len);

@implementation LibOrgBouncycastleBcpgBCPGOutputStream

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg {
  LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_(self, outArg);
  return self;
}

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                                   withInt:(jint)tag {
  LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_(self, outArg, tag);
  return self;
}

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                                   withInt:(jint)tag
                                  withLong:(jlong)length
                               withBoolean:(jboolean)oldFormat {
  LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_withLong_withBoolean_(self, outArg, tag, length, oldFormat);
  return self;
}

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                                   withInt:(jint)tag
                                  withLong:(jlong)length {
  LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_withLong_(self, outArg, tag, length);
  return self;
}

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                                   withInt:(jint)tag
                             withByteArray:(IOSByteArray *)buffer {
  LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_withByteArray_(self, outArg, tag, buffer);
  return self;
}

- (void)writeNewPacketLengthWithLong:(jlong)bodyLen {
  LibOrgBouncycastleBcpgBCPGOutputStream_writeNewPacketLengthWithLong_(self, bodyLen);
}

- (void)writeHeaderWithInt:(jint)tag
               withBoolean:(jboolean)oldPackets
               withBoolean:(jboolean)partial
                  withLong:(jlong)bodyLen {
  LibOrgBouncycastleBcpgBCPGOutputStream_writeHeaderWithInt_withBoolean_withBoolean_withLong_(self, tag, oldPackets, partial, bodyLen);
}

- (void)partialFlushWithBoolean:(jboolean)isLast {
  LibOrgBouncycastleBcpgBCPGOutputStream_partialFlushWithBoolean_(self, isLast);
}

- (void)writePartialWithByte:(jbyte)b {
  LibOrgBouncycastleBcpgBCPGOutputStream_writePartialWithByte_(self, b);
}

- (void)writePartialWithByteArray:(IOSByteArray *)buf
                          withInt:(jint)off
                          withInt:(jint)len {
  LibOrgBouncycastleBcpgBCPGOutputStream_writePartialWithByteArray_withInt_withInt_(self, buf, off, len);
}

- (void)writeWithInt:(jint)b {
  if (partialBuffer_ != nil) {
    LibOrgBouncycastleBcpgBCPGOutputStream_writePartialWithByte_(self, (jbyte) b);
  }
  else {
    [((JavaIoOutputStream *) nil_chk(out_)) writeWithInt:b];
  }
}

- (void)writeWithByteArray:(IOSByteArray *)bytes
                   withInt:(jint)off
                   withInt:(jint)len {
  if (partialBuffer_ != nil) {
    LibOrgBouncycastleBcpgBCPGOutputStream_writePartialWithByteArray_withInt_withInt_(self, bytes, off, len);
  }
  else {
    [((JavaIoOutputStream *) nil_chk(out_)) writeWithByteArray:bytes withInt:off withInt:len];
  }
}

- (void)writePacketWithLibOrgBouncycastleBcpgContainedPacket:(LibOrgBouncycastleBcpgContainedPacket *)p {
  [((LibOrgBouncycastleBcpgContainedPacket *) nil_chk(p)) encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:self];
}

- (void)writePacketWithInt:(jint)tag
             withByteArray:(IOSByteArray *)body
               withBoolean:(jboolean)oldFormat {
  LibOrgBouncycastleBcpgBCPGOutputStream_writeHeaderWithInt_withBoolean_withBoolean_withLong_(self, tag, oldFormat, false, ((IOSByteArray *) nil_chk(body))->size_);
  [self writeWithByteArray:body];
}

- (void)writeObjectWithLibOrgBouncycastleBcpgBCPGObject:(LibOrgBouncycastleBcpgBCPGObject *)o {
  [((LibOrgBouncycastleBcpgBCPGObject *) nil_chk(o)) encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:self];
}

- (void)flush {
  [((JavaIoOutputStream *) nil_chk(out_)) flush];
}

- (void)finish {
  if (partialBuffer_ != nil) {
    LibOrgBouncycastleBcpgBCPGOutputStream_partialFlushWithBoolean_(self, true);
    LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(partialBuffer_, (jbyte) 0);
    partialBuffer_ = nil;
  }
}

- (void)close {
  [self finish];
  [((JavaIoOutputStream *) nil_chk(out_)) flush];
  [((JavaIoOutputStream *) nil_chk(out_)) close];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, 2, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, 2, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, 2, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, 2, -1, -1, -1 },
    { NULL, "V", 0x2, 6, 7, 2, -1, -1, -1 },
    { NULL, "V", 0x2, 8, 9, 2, -1, -1, -1 },
    { NULL, "V", 0x2, 10, 11, 2, -1, -1, -1 },
    { NULL, "V", 0x2, 12, 13, 2, -1, -1, -1 },
    { NULL, "V", 0x2, 12, 14, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 15, 16, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 15, 14, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 17, 18, 2, -1, -1, -1 },
    { NULL, "V", 0x0, 17, 19, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 20, 21, 2, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoOutputStream:);
  methods[1].selector = @selector(initWithJavaIoOutputStream:withInt:);
  methods[2].selector = @selector(initWithJavaIoOutputStream:withInt:withLong:withBoolean:);
  methods[3].selector = @selector(initWithJavaIoOutputStream:withInt:withLong:);
  methods[4].selector = @selector(initWithJavaIoOutputStream:withInt:withByteArray:);
  methods[5].selector = @selector(writeNewPacketLengthWithLong:);
  methods[6].selector = @selector(writeHeaderWithInt:withBoolean:withBoolean:withLong:);
  methods[7].selector = @selector(partialFlushWithBoolean:);
  methods[8].selector = @selector(writePartialWithByte:);
  methods[9].selector = @selector(writePartialWithByteArray:withInt:withInt:);
  methods[10].selector = @selector(writeWithInt:);
  methods[11].selector = @selector(writeWithByteArray:withInt:withInt:);
  methods[12].selector = @selector(writePacketWithLibOrgBouncycastleBcpgContainedPacket:);
  methods[13].selector = @selector(writePacketWithInt:withByteArray:withBoolean:);
  methods[14].selector = @selector(writeObjectWithLibOrgBouncycastleBcpgBCPGObject:);
  methods[15].selector = @selector(flush);
  methods[16].selector = @selector(finish);
  methods[17].selector = @selector(close);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "out_", "LJavaIoOutputStream;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "partialBuffer_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "partialBufferLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "partialPower_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "partialOffset_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "BUF_SIZE_POWER", "I", .constantValue.asInt = LibOrgBouncycastleBcpgBCPGOutputStream_BUF_SIZE_POWER, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoOutputStream;", "LJavaIoOutputStream;I", "LJavaIoIOException;", "LJavaIoOutputStream;IJZ", "LJavaIoOutputStream;IJ", "LJavaIoOutputStream;I[B", "writeNewPacketLength", "J", "writeHeader", "IZZJ", "partialFlush", "Z", "writePartial", "B", "[BII", "write", "I", "writePacket", "LLibOrgBouncycastleBcpgContainedPacket;", "I[BZ", "writeObject", "LLibOrgBouncycastleBcpgBCPGObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgBCPGOutputStream = { "BCPGOutputStream", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0x1, 18, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgBCPGOutputStream;
}

@end

void LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_(LibOrgBouncycastleBcpgBCPGOutputStream *self, JavaIoOutputStream *outArg) {
  JavaIoOutputStream_init(self);
  self->out_ = outArg;
}

LibOrgBouncycastleBcpgBCPGOutputStream *new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_(JavaIoOutputStream *outArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgBCPGOutputStream, initWithJavaIoOutputStream_, outArg)
}

LibOrgBouncycastleBcpgBCPGOutputStream *create_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_(JavaIoOutputStream *outArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgBCPGOutputStream, initWithJavaIoOutputStream_, outArg)
}

void LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_(LibOrgBouncycastleBcpgBCPGOutputStream *self, JavaIoOutputStream *outArg, jint tag) {
  JavaIoOutputStream_init(self);
  self->out_ = outArg;
  LibOrgBouncycastleBcpgBCPGOutputStream_writeHeaderWithInt_withBoolean_withBoolean_withLong_(self, tag, true, true, 0);
}

LibOrgBouncycastleBcpgBCPGOutputStream *new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_(JavaIoOutputStream *outArg, jint tag) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgBCPGOutputStream, initWithJavaIoOutputStream_withInt_, outArg, tag)
}

LibOrgBouncycastleBcpgBCPGOutputStream *create_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_(JavaIoOutputStream *outArg, jint tag) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgBCPGOutputStream, initWithJavaIoOutputStream_withInt_, outArg, tag)
}

void LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_withLong_withBoolean_(LibOrgBouncycastleBcpgBCPGOutputStream *self, JavaIoOutputStream *outArg, jint tag, jlong length, jboolean oldFormat) {
  JavaIoOutputStream_init(self);
  self->out_ = outArg;
  if (length > (jlong) 0xFFFFFFFFLL) {
    LibOrgBouncycastleBcpgBCPGOutputStream_writeHeaderWithInt_withBoolean_withBoolean_withLong_(self, tag, false, true, 0);
    self->partialBufferLength_ = JreLShift32(1, LibOrgBouncycastleBcpgBCPGOutputStream_BUF_SIZE_POWER);
    self->partialBuffer_ = [IOSByteArray newArrayWithLength:self->partialBufferLength_];
    self->partialPower_ = LibOrgBouncycastleBcpgBCPGOutputStream_BUF_SIZE_POWER;
    self->partialOffset_ = 0;
  }
  else {
    LibOrgBouncycastleBcpgBCPGOutputStream_writeHeaderWithInt_withBoolean_withBoolean_withLong_(self, tag, oldFormat, false, length);
  }
}

LibOrgBouncycastleBcpgBCPGOutputStream *new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_withLong_withBoolean_(JavaIoOutputStream *outArg, jint tag, jlong length, jboolean oldFormat) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgBCPGOutputStream, initWithJavaIoOutputStream_withInt_withLong_withBoolean_, outArg, tag, length, oldFormat)
}

LibOrgBouncycastleBcpgBCPGOutputStream *create_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_withLong_withBoolean_(JavaIoOutputStream *outArg, jint tag, jlong length, jboolean oldFormat) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgBCPGOutputStream, initWithJavaIoOutputStream_withInt_withLong_withBoolean_, outArg, tag, length, oldFormat)
}

void LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_withLong_(LibOrgBouncycastleBcpgBCPGOutputStream *self, JavaIoOutputStream *outArg, jint tag, jlong length) {
  JavaIoOutputStream_init(self);
  self->out_ = outArg;
  LibOrgBouncycastleBcpgBCPGOutputStream_writeHeaderWithInt_withBoolean_withBoolean_withLong_(self, tag, false, false, length);
}

LibOrgBouncycastleBcpgBCPGOutputStream *new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_withLong_(JavaIoOutputStream *outArg, jint tag, jlong length) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgBCPGOutputStream, initWithJavaIoOutputStream_withInt_withLong_, outArg, tag, length)
}

LibOrgBouncycastleBcpgBCPGOutputStream *create_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_withLong_(JavaIoOutputStream *outArg, jint tag, jlong length) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgBCPGOutputStream, initWithJavaIoOutputStream_withInt_withLong_, outArg, tag, length)
}

void LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_withByteArray_(LibOrgBouncycastleBcpgBCPGOutputStream *self, JavaIoOutputStream *outArg, jint tag, IOSByteArray *buffer) {
  JavaIoOutputStream_init(self);
  self->out_ = outArg;
  LibOrgBouncycastleBcpgBCPGOutputStream_writeHeaderWithInt_withBoolean_withBoolean_withLong_(self, tag, false, true, 0);
  self->partialBuffer_ = buffer;
  jint length = ((IOSByteArray *) nil_chk(self->partialBuffer_))->size_;
  for (self->partialPower_ = 0; length != 1; self->partialPower_++) {
    JreURShiftAssignInt(&length, 1);
  }
  if (self->partialPower_ > 30) {
    @throw new_JavaIoIOException_initWithNSString_(@"Buffer cannot be greater than 2^30 in length.");
  }
  self->partialBufferLength_ = JreLShift32(1, self->partialPower_);
  self->partialOffset_ = 0;
}

LibOrgBouncycastleBcpgBCPGOutputStream *new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_withByteArray_(JavaIoOutputStream *outArg, jint tag, IOSByteArray *buffer) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgBCPGOutputStream, initWithJavaIoOutputStream_withInt_withByteArray_, outArg, tag, buffer)
}

LibOrgBouncycastleBcpgBCPGOutputStream *create_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_withByteArray_(JavaIoOutputStream *outArg, jint tag, IOSByteArray *buffer) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgBCPGOutputStream, initWithJavaIoOutputStream_withInt_withByteArray_, outArg, tag, buffer)
}

void LibOrgBouncycastleBcpgBCPGOutputStream_writeNewPacketLengthWithLong_(LibOrgBouncycastleBcpgBCPGOutputStream *self, jlong bodyLen) {
  if (bodyLen < 192) {
    [((JavaIoOutputStream *) nil_chk(self->out_)) writeWithInt:(jbyte) bodyLen];
  }
  else if (bodyLen <= 8383) {
    bodyLen -= 192;
    [((JavaIoOutputStream *) nil_chk(self->out_)) writeWithInt:(jbyte) (((JreRShift64(bodyLen, 8)) & (jint) 0xff) + 192)];
    [((JavaIoOutputStream *) nil_chk(self->out_)) writeWithInt:(jbyte) bodyLen];
  }
  else {
    [((JavaIoOutputStream *) nil_chk(self->out_)) writeWithInt:(jint) 0xff];
    [((JavaIoOutputStream *) nil_chk(self->out_)) writeWithInt:(jbyte) (JreRShift64(bodyLen, 24))];
    [((JavaIoOutputStream *) nil_chk(self->out_)) writeWithInt:(jbyte) (JreRShift64(bodyLen, 16))];
    [((JavaIoOutputStream *) nil_chk(self->out_)) writeWithInt:(jbyte) (JreRShift64(bodyLen, 8))];
    [((JavaIoOutputStream *) nil_chk(self->out_)) writeWithInt:(jbyte) bodyLen];
  }
}

void LibOrgBouncycastleBcpgBCPGOutputStream_writeHeaderWithInt_withBoolean_withBoolean_withLong_(LibOrgBouncycastleBcpgBCPGOutputStream *self, jint tag, jboolean oldPackets, jboolean partial, jlong bodyLen) {
  jint hdr = (jint) 0x80;
  if (self->partialBuffer_ != nil) {
    LibOrgBouncycastleBcpgBCPGOutputStream_partialFlushWithBoolean_(self, true);
    self->partialBuffer_ = nil;
  }
  if (oldPackets) {
    hdr |= JreLShift32(tag, 2);
    if (partial) {
      [self writeWithInt:hdr | (jint) 0x03];
    }
    else {
      if (bodyLen <= (jint) 0xff) {
        [self writeWithInt:hdr];
        [self writeWithInt:(jbyte) bodyLen];
      }
      else if (bodyLen <= (jint) 0xffff) {
        [self writeWithInt:hdr | (jint) 0x01];
        [self writeWithInt:(jbyte) (JreRShift64(bodyLen, 8))];
        [self writeWithInt:(jbyte) (bodyLen)];
      }
      else {
        [self writeWithInt:hdr | (jint) 0x02];
        [self writeWithInt:(jbyte) (JreRShift64(bodyLen, 24))];
        [self writeWithInt:(jbyte) (JreRShift64(bodyLen, 16))];
        [self writeWithInt:(jbyte) (JreRShift64(bodyLen, 8))];
        [self writeWithInt:(jbyte) bodyLen];
      }
    }
  }
  else {
    hdr |= (jint) 0x40 | tag;
    [self writeWithInt:hdr];
    if (partial) {
      self->partialOffset_ = 0;
    }
    else {
      LibOrgBouncycastleBcpgBCPGOutputStream_writeNewPacketLengthWithLong_(self, bodyLen);
    }
  }
}

void LibOrgBouncycastleBcpgBCPGOutputStream_partialFlushWithBoolean_(LibOrgBouncycastleBcpgBCPGOutputStream *self, jboolean isLast) {
  if (isLast) {
    LibOrgBouncycastleBcpgBCPGOutputStream_writeNewPacketLengthWithLong_(self, self->partialOffset_);
    [((JavaIoOutputStream *) nil_chk(self->out_)) writeWithByteArray:self->partialBuffer_ withInt:0 withInt:self->partialOffset_];
  }
  else {
    [((JavaIoOutputStream *) nil_chk(self->out_)) writeWithInt:(jint) 0xE0 | self->partialPower_];
    [((JavaIoOutputStream *) nil_chk(self->out_)) writeWithByteArray:self->partialBuffer_ withInt:0 withInt:self->partialBufferLength_];
  }
  self->partialOffset_ = 0;
}

void LibOrgBouncycastleBcpgBCPGOutputStream_writePartialWithByte_(LibOrgBouncycastleBcpgBCPGOutputStream *self, jbyte b) {
  if (self->partialOffset_ == self->partialBufferLength_) {
    LibOrgBouncycastleBcpgBCPGOutputStream_partialFlushWithBoolean_(self, false);
  }
  *IOSByteArray_GetRef(nil_chk(self->partialBuffer_), self->partialOffset_++) = b;
}

void LibOrgBouncycastleBcpgBCPGOutputStream_writePartialWithByteArray_withInt_withInt_(LibOrgBouncycastleBcpgBCPGOutputStream *self, IOSByteArray *buf, jint off, jint len) {
  if (self->partialOffset_ == self->partialBufferLength_) {
    LibOrgBouncycastleBcpgBCPGOutputStream_partialFlushWithBoolean_(self, false);
  }
  if (len <= (self->partialBufferLength_ - self->partialOffset_)) {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, off, self->partialBuffer_, self->partialOffset_, len);
    self->partialOffset_ += len;
  }
  else {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, off, self->partialBuffer_, self->partialOffset_, self->partialBufferLength_ - self->partialOffset_);
    off += self->partialBufferLength_ - self->partialOffset_;
    len -= self->partialBufferLength_ - self->partialOffset_;
    LibOrgBouncycastleBcpgBCPGOutputStream_partialFlushWithBoolean_(self, false);
    while (len > self->partialBufferLength_) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, off, self->partialBuffer_, 0, self->partialBufferLength_);
      off += self->partialBufferLength_;
      len -= self->partialBufferLength_;
      LibOrgBouncycastleBcpgBCPGOutputStream_partialFlushWithBoolean_(self, false);
    }
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, off, self->partialBuffer_, 0, len);
    self->partialOffset_ += len;
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgBCPGOutputStream)