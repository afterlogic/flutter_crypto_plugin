//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPCompressedDataGenerator.java
//

#include "BCPGOutputStream.h"
#include "CBZip2OutputStream.h"
#include "CompressionAlgorithmTags.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PGPCompressedDataGenerator.h"
#include "PacketTags.h"
#include "WrappedGeneratorStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/util/zip/Deflater.h"
#include "java/util/zip/DeflaterOutputStream.h"

@interface LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator () {
 @public
  jint algorithm_;
  jint compression_;
  JavaIoOutputStream *dOut_;
  LibOrgBouncycastleBcpgBCPGOutputStream *pkOut_;
}

- (void)doOpen;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator, dOut_, JavaIoOutputStream *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator, pkOut_, LibOrgBouncycastleBcpgBCPGOutputStream *)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_doOpen(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *self);

@interface LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream : LibOrgBouncycastleApacheBzip2CBZip2OutputStream

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)output;

- (void)close;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream_initWithJavaIoOutputStream_(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream *self, JavaIoOutputStream *output);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream *new_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream_initWithJavaIoOutputStream_(JavaIoOutputStream *output) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream *create_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream_initWithJavaIoOutputStream_(JavaIoOutputStream *output);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream)

@interface LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream : JavaUtilZipDeflaterOutputStream

- (instancetype)initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator:(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *)outer$
                                                     withJavaIoOutputStream:(JavaIoOutputStream *)output
                                                                    withInt:(jint)compression
                                                                withBoolean:(jboolean)nowrap;

- (void)close;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream_initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_withJavaIoOutputStream_withInt_withBoolean_(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream *self, LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *outer$, JavaIoOutputStream *output, jint compression, jboolean nowrap);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream *new_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream_initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_withJavaIoOutputStream_withInt_withBoolean_(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *outer$, JavaIoOutputStream *output, jint compression, jboolean nowrap) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream *create_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream_initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_withJavaIoOutputStream_withInt_withBoolean_(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *outer$, JavaIoOutputStream *output, jint compression, jboolean nowrap);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream)

@implementation LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator

- (instancetype)initWithInt:(jint)algorithm {
  LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_(self, algorithm);
  return self;
}

- (instancetype)initWithInt:(jint)algorithm
                    withInt:(jint)compression {
  LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_withInt_(self, algorithm, compression);
  return self;
}

- (JavaIoOutputStream *)openWithJavaIoOutputStream:(JavaIoOutputStream *)outArg {
  if (dOut_ != nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"generator already in open state");
  }
  self->pkOut_ = new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_(outArg, LibOrgBouncycastleBcpgPacketTags_COMPRESSED_DATA);
  LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_doOpen(self);
  return new_LibOrgBouncycastleOpenpgpWrappedGeneratorStream_initWithJavaIoOutputStream_withLibOrgBouncycastleOpenpgpStreamGenerator_(dOut_, self);
}

- (JavaIoOutputStream *)openWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                                     withByteArray:(IOSByteArray *)buffer {
  if (dOut_ != nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"generator already in open state");
  }
  self->pkOut_ = new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_withInt_withByteArray_(outArg, LibOrgBouncycastleBcpgPacketTags_COMPRESSED_DATA, buffer);
  LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_doOpen(self);
  return new_LibOrgBouncycastleOpenpgpWrappedGeneratorStream_initWithJavaIoOutputStream_withLibOrgBouncycastleOpenpgpStreamGenerator_(dOut_, self);
}

- (void)doOpen {
  LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_doOpen(self);
}

- (void)close {
  if (dOut_ != nil) {
    if (dOut_ != pkOut_) {
      [dOut_ close];
    }
    dOut_ = nil;
    [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(pkOut_)) finish];
    [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(pkOut_)) flush];
    pkOut_ = nil;
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LJavaIoOutputStream;", 0x1, 2, 3, 4, -1, -1, -1 },
    { NULL, "LJavaIoOutputStream;", 0x1, 2, 5, 6, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, 4, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 4, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:);
  methods[1].selector = @selector(initWithInt:withInt:);
  methods[2].selector = @selector(openWithJavaIoOutputStream:);
  methods[3].selector = @selector(openWithJavaIoOutputStream:withByteArray:);
  methods[4].selector = @selector(doOpen);
  methods[5].selector = @selector(close);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "algorithm_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "compression_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "dOut_", "LJavaIoOutputStream;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "pkOut_", "LLibOrgBouncycastleBcpgBCPGOutputStream;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I", "II", "open", "LJavaIoOutputStream;", "LJavaIoIOException;", "LJavaIoOutputStream;[B", "LJavaIoIOException;LLibOrgBouncycastleOpenpgpPGPException;", "LLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream;LLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator = { "PGPCompressedDataGenerator", "lib.org.bouncycastle.openpgp", ptrTable, methods, fields, 7, 0x1, 6, 4, -1, 7, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator;
}

@end

void LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *self, jint algorithm) {
  LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_withInt_(self, algorithm, JavaUtilZipDeflater_DEFAULT_COMPRESSION);
}

LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *new_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_(jint algorithm) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator, initWithInt_, algorithm)
}

LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *create_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_(jint algorithm) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator, initWithInt_, algorithm)
}

void LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_withInt_(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *self, jint algorithm, jint compression) {
  NSObject_init(self);
  switch (algorithm) {
    case LibOrgBouncycastleBcpgCompressionAlgorithmTags_UNCOMPRESSED:
    case LibOrgBouncycastleBcpgCompressionAlgorithmTags_ZIP:
    case LibOrgBouncycastleBcpgCompressionAlgorithmTags_ZLIB:
    case LibOrgBouncycastleBcpgCompressionAlgorithmTags_BZIP2:
    break;
    default:
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unknown compression algorithm");
  }
  if (compression != JavaUtilZipDeflater_DEFAULT_COMPRESSION) {
    if ((compression < JavaUtilZipDeflater_NO_COMPRESSION) || (compression > JavaUtilZipDeflater_BEST_COMPRESSION)) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"unknown compression level: ", compression));
    }
  }
  self->algorithm_ = algorithm;
  self->compression_ = compression;
}

LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *new_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_withInt_(jint algorithm, jint compression) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator, initWithInt_withInt_, algorithm, compression)
}

LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *create_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_withInt_(jint algorithm, jint compression) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator, initWithInt_withInt_, algorithm, compression)
}

void LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_doOpen(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *self) {
  [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(self->pkOut_)) writeWithInt:self->algorithm_];
  switch (self->algorithm_) {
    case LibOrgBouncycastleBcpgCompressionAlgorithmTags_UNCOMPRESSED:
    self->dOut_ = self->pkOut_;
    break;
    case LibOrgBouncycastleBcpgCompressionAlgorithmTags_ZIP:
    self->dOut_ = new_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream_initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_withJavaIoOutputStream_withInt_withBoolean_(self, self->pkOut_, self->compression_, true);
    break;
    case LibOrgBouncycastleBcpgCompressionAlgorithmTags_ZLIB:
    self->dOut_ = new_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream_initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_withJavaIoOutputStream_withInt_withBoolean_(self, self->pkOut_, self->compression_, false);
    break;
    case LibOrgBouncycastleBcpgCompressionAlgorithmTags_BZIP2:
    self->dOut_ = new_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream_initWithJavaIoOutputStream_(self->pkOut_);
    break;
    default:
    @throw new_JavaLangIllegalStateException_init();
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator)

@implementation LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream_initWithJavaIoOutputStream_(self, output);
  return self;
}

- (void)close {
  [self finish];
}

- (void)dealloc {
  JreCheckFinalize(self, [LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream class]);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoOutputStream:);
  methods[1].selector = @selector(close);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LJavaIoOutputStream;", "LJavaIoIOException;", "LLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream = { "SafeCBZip2OutputStream", "lib.org.bouncycastle.openpgp", ptrTable, methods, NULL, 7, 0xa, 2, 0, 2, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream;
}

@end

void LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream_initWithJavaIoOutputStream_(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream *self, JavaIoOutputStream *output) {
  LibOrgBouncycastleApacheBzip2CBZip2OutputStream_initWithJavaIoOutputStream_(self, output);
}

LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream *new_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream_initWithJavaIoOutputStream_(JavaIoOutputStream *output) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream, initWithJavaIoOutputStream_, output)
}

LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream *create_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream_initWithJavaIoOutputStream_(JavaIoOutputStream *output) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream, initWithJavaIoOutputStream_, output)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeCBZip2OutputStream)

@implementation LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream

- (instancetype)initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator:(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *)outer$
                                                     withJavaIoOutputStream:(JavaIoOutputStream *)output
                                                                    withInt:(jint)compression
                                                                withBoolean:(jboolean)nowrap {
  LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream_initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_withJavaIoOutputStream_withInt_withBoolean_(self, outer$, output, compression, nowrap);
  return self;
}

- (void)close {
  [self finish];
  [((JavaUtilZipDeflater *) nil_chk(def_)) end];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator:withJavaIoOutputStream:withInt:withBoolean:);
  methods[1].selector = @selector(close);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LJavaIoOutputStream;IZ", "LJavaIoIOException;", "LLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream = { "SafeDeflaterOutputStream", "lib.org.bouncycastle.openpgp", ptrTable, methods, NULL, 7, 0x2, 2, 0, 2, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream;
}

@end

void LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream_initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_withJavaIoOutputStream_withInt_withBoolean_(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream *self, LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *outer$, JavaIoOutputStream *output, jint compression, jboolean nowrap) {
  JavaUtilZipDeflaterOutputStream_initWithJavaIoOutputStream_withJavaUtilZipDeflater_(self, output, new_JavaUtilZipDeflater_initWithInt_withBoolean_(compression, nowrap));
}

LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream *new_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream_initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_withJavaIoOutputStream_withInt_withBoolean_(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *outer$, JavaIoOutputStream *output, jint compression, jboolean nowrap) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream, initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_withJavaIoOutputStream_withInt_withBoolean_, outer$, output, compression, nowrap)
}

LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream *create_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream_initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_withJavaIoOutputStream_withInt_withBoolean_(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *outer$, JavaIoOutputStream *output, jint compression, jboolean nowrap) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream, initWithLibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_withJavaIoOutputStream_withInt_withBoolean_, outer$, output, compression, nowrap)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_SafeDeflaterOutputStream)
