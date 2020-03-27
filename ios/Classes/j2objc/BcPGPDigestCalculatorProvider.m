//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/bc/BcPGPDigestCalculatorProvider.java
//

#include "BcImplProvider.h"
#include "BcPGPDigestCalculatorProvider.h"
#include "Digest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PGPDigestCalculator.h"
#include "java/io/OutputStream.h"

@class LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream;

@interface LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1 : NSObject < LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator > {
 @public
  jint val$algorithm_;
  LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *val$stream_;
  id<LibOrgBouncycastleCryptoDigest> val$dig_;
}

- (instancetype)initWithInt:(jint)capture$0
withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream:(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *)capture$1
withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)capture$2;

- (jint)getAlgorithm;

- (JavaIoOutputStream *)getOutputStream;

- (IOSByteArray *)getDigest;

- (void)reset;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1 *self, jint capture$0, LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *capture$1, id<LibOrgBouncycastleCryptoDigest> capture$2);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1 *new_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_withLibOrgBouncycastleCryptoDigest_(jint capture$0, LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *capture$1, id<LibOrgBouncycastleCryptoDigest> capture$2) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1 *create_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_withLibOrgBouncycastleCryptoDigest_(jint capture$0, LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *capture$1, id<LibOrgBouncycastleCryptoDigest> capture$2);

@interface LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream : JavaIoOutputStream {
 @public
  id<LibOrgBouncycastleCryptoDigest> dig_;
}

- (instancetype)initWithLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider:(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *)outer$
                                                      withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)dig;

- (void)writeWithByteArray:(IOSByteArray *)bytes
                   withInt:(jint)off
                   withInt:(jint)len;

- (void)writeWithByteArray:(IOSByteArray *)bytes;

- (void)writeWithInt:(jint)b;

- (IOSByteArray *)getDigest;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream, dig_, id<LibOrgBouncycastleCryptoDigest>)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *self, LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *outer$, id<LibOrgBouncycastleCryptoDigest> dig);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *new_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *outer$, id<LibOrgBouncycastleCryptoDigest> dig) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *create_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *outer$, id<LibOrgBouncycastleCryptoDigest> dig);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream)

@implementation LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)getWithInt:(jint)algorithm {
  id<LibOrgBouncycastleCryptoDigest> dig = LibOrgBouncycastleOpenpgpOperatorBcBcImplProvider_createDigestWithInt_(algorithm);
  LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *stream = new_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_withLibOrgBouncycastleCryptoDigest_(self, dig);
  return new_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_withLibOrgBouncycastleCryptoDigest_(algorithm, stream, dig);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator;", 0x1, 0, 1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getWithInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "get", "I", "LLibOrgBouncycastleOpenpgpPGPException;", "LLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider = { "BcPGPDigestCalculatorProvider", "lib.org.bouncycastle.openpgp.operator.bc", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, 3, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider;
}

@end

void LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_init(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *self) {
  NSObject_init(self);
}

LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *new_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider, init)
}

LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *create_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider)

@implementation LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1

- (instancetype)initWithInt:(jint)capture$0
withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream:(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *)capture$1
withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)capture$2 {
  LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_withLibOrgBouncycastleCryptoDigest_(self, capture$0, capture$1, capture$2);
  return self;
}

- (jint)getAlgorithm {
  return val$algorithm_;
}

- (JavaIoOutputStream *)getOutputStream {
  return val$stream_;
}

- (IOSByteArray *)getDigest {
  return [((LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *) nil_chk(val$stream_)) getDigest];
}

- (void)reset {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(val$dig_)) reset];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaIoOutputStream;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream:withLibOrgBouncycastleCryptoDigest:);
  methods[1].selector = @selector(getAlgorithm);
  methods[2].selector = @selector(getOutputStream);
  methods[3].selector = @selector(getDigest);
  methods[4].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "val$algorithm_", "I", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$stream_", "LLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$dig_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider;", "getWithInt:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1 = { "", "lib.org.bouncycastle.openpgp.operator.bc", ptrTable, methods, fields, 7, 0x8010, 5, 3, 0, -1, 1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1;
}

@end

void LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1 *self, jint capture$0, LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *capture$1, id<LibOrgBouncycastleCryptoDigest> capture$2) {
  self->val$algorithm_ = capture$0;
  self->val$stream_ = capture$1;
  self->val$dig_ = capture$2;
  NSObject_init(self);
}

LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1 *new_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_withLibOrgBouncycastleCryptoDigest_(jint capture$0, LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *capture$1, id<LibOrgBouncycastleCryptoDigest> capture$2) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1, initWithInt_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_withLibOrgBouncycastleCryptoDigest_, capture$0, capture$1, capture$2)
}

LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1 *create_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_withLibOrgBouncycastleCryptoDigest_(jint capture$0, LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *capture$1, id<LibOrgBouncycastleCryptoDigest> capture$2) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_1, initWithInt_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_withLibOrgBouncycastleCryptoDigest_, capture$0, capture$1, capture$2)
}

@implementation LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream

- (instancetype)initWithLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider:(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *)outer$
                                                      withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)dig {
  LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_withLibOrgBouncycastleCryptoDigest_(self, outer$, dig);
  return self;
}

- (void)writeWithByteArray:(IOSByteArray *)bytes
                   withInt:(jint)off
                   withInt:(jint)len {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(dig_)) updateWithByteArray:bytes withInt:off withInt:len];
}

- (void)writeWithByteArray:(IOSByteArray *)bytes {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(dig_)) updateWithByteArray:bytes withInt:0 withInt:((IOSByteArray *) nil_chk(bytes))->size_];
}

- (void)writeWithInt:(jint)b {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(dig_)) updateWithByte:(jbyte) b];
}

- (IOSByteArray *)getDigest {
  IOSByteArray *d = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(dig_)) getDigestSize]];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(dig_)) doFinalWithByteArray:d withInt:0];
  return d;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 4, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 5, 3, -1, -1, -1 },
    { NULL, "[B", 0x0, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider:withLibOrgBouncycastleCryptoDigest:);
  methods[1].selector = @selector(writeWithByteArray:withInt:withInt:);
  methods[2].selector = @selector(writeWithByteArray:);
  methods[3].selector = @selector(writeWithInt:);
  methods[4].selector = @selector(getDigest);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "dig_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigest;", "write", "[BII", "LJavaIoIOException;", "[B", "I", "LLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream = { "DigestOutputStream", "lib.org.bouncycastle.openpgp.operator.bc", ptrTable, methods, fields, 7, 0x2, 5, 1, 6, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream;
}

@end

void LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *self, LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *outer$, id<LibOrgBouncycastleCryptoDigest> dig) {
  JavaIoOutputStream_init(self);
  self->dig_ = dig;
}

LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *new_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *outer$, id<LibOrgBouncycastleCryptoDigest> dig) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream, initWithLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_withLibOrgBouncycastleCryptoDigest_, outer$, dig)
}

LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream *create_LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *outer$, id<LibOrgBouncycastleCryptoDigest> dig) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream, initWithLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_withLibOrgBouncycastleCryptoDigest_, outer$, dig)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_DigestOutputStream)
