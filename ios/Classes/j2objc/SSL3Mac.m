//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/SSL3Mac.java
//

#include "Arrays.h"
#include "CipherParameters.h"
#include "Digest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "SSL3Mac.h"

@interface LibOrgBouncycastleCryptoTlsSSL3Mac () {
 @public
  id<LibOrgBouncycastleCryptoDigest> digest_;
  jint padLength_;
  IOSByteArray *secret_;
}

+ (IOSByteArray *)genPadWithByte:(jbyte)b
                         withInt:(jint)count;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsSSL3Mac, digest_, id<LibOrgBouncycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsSSL3Mac, secret_, IOSByteArray *)

inline jbyte LibOrgBouncycastleCryptoTlsSSL3Mac_get_IPAD_BYTE(void);
#define LibOrgBouncycastleCryptoTlsSSL3Mac_IPAD_BYTE 54
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsSSL3Mac, IPAD_BYTE, jbyte)

inline jbyte LibOrgBouncycastleCryptoTlsSSL3Mac_get_OPAD_BYTE(void);
#define LibOrgBouncycastleCryptoTlsSSL3Mac_OPAD_BYTE 92
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsSSL3Mac, OPAD_BYTE, jbyte)

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoTlsSSL3Mac_genPadWithByte_withInt_(jbyte b, jint count);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoTlsSSL3Mac)

IOSByteArray *LibOrgBouncycastleCryptoTlsSSL3Mac_IPAD;
IOSByteArray *LibOrgBouncycastleCryptoTlsSSL3Mac_OPAD;

@implementation LibOrgBouncycastleCryptoTlsSSL3Mac

+ (IOSByteArray *)IPAD {
  return LibOrgBouncycastleCryptoTlsSSL3Mac_IPAD;
}

+ (IOSByteArray *)OPAD {
  return LibOrgBouncycastleCryptoTlsSSL3Mac_OPAD;
}

- (instancetype)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest {
  LibOrgBouncycastleCryptoTlsSSL3Mac_initWithLibOrgBouncycastleCryptoDigest_(self, digest);
  return self;
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$$", [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getAlgorithmName], @"/SSL3MAC");
}

- (id<LibOrgBouncycastleCryptoDigest>)getUnderlyingDigest {
  return digest_;
}

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  secret_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleCryptoParamsKeyParameter *) nil_chk(((LibOrgBouncycastleCryptoParamsKeyParameter *) cast_chk(params, [LibOrgBouncycastleCryptoParamsKeyParameter class])))) getKey]);
  [self reset];
}

- (jint)getMacSize {
  return [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize];
}

- (void)updateWithByte:(jbyte)inArg {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByte:inArg];
}

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:inArg withInt:inOff withInt:len];
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  IOSByteArray *tmp = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize]];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:tmp withInt:0];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:secret_ withInt:0 withInt:((IOSByteArray *) nil_chk(secret_))->size_];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:LibOrgBouncycastleCryptoTlsSSL3Mac_OPAD withInt:0 withInt:padLength_];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:tmp withInt:0 withInt:tmp->size_];
  jint len = [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:outArg withInt:outOff];
  [self reset];
  return len;
}

- (void)reset {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) reset];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:secret_ withInt:0 withInt:((IOSByteArray *) nil_chk(secret_))->size_];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:LibOrgBouncycastleCryptoTlsSSL3Mac_IPAD withInt:0 withInt:padLength_];
}

+ (IOSByteArray *)genPadWithByte:(jbyte)b
                         withInt:(jint)count {
  return LibOrgBouncycastleCryptoTlsSSL3Mac_genPadWithByte_withInt_(b, count);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoDigest;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0xa, 8, 9, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoDigest:);
  methods[1].selector = @selector(getAlgorithmName);
  methods[2].selector = @selector(getUnderlyingDigest);
  methods[3].selector = @selector(init__WithLibOrgBouncycastleCryptoCipherParameters:);
  methods[4].selector = @selector(getMacSize);
  methods[5].selector = @selector(updateWithByte:);
  methods[6].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[7].selector = @selector(doFinalWithByteArray:withInt:);
  methods[8].selector = @selector(reset);
  methods[9].selector = @selector(genPadWithByte:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "IPAD_BYTE", "B", .constantValue.asChar = LibOrgBouncycastleCryptoTlsSSL3Mac_IPAD_BYTE, 0x1a, -1, -1, -1, -1 },
    { "OPAD_BYTE", "B", .constantValue.asChar = LibOrgBouncycastleCryptoTlsSSL3Mac_OPAD_BYTE, 0x1a, -1, -1, -1, -1 },
    { "IPAD", "[B", .constantValue.asLong = 0, 0x18, -1, 10, -1, -1 },
    { "OPAD", "[B", .constantValue.asLong = 0, 0x18, -1, 11, -1, -1 },
    { "digest_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "padLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "secret_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigest;", "init", "LLibOrgBouncycastleCryptoCipherParameters;", "update", "B", "[BII", "doFinal", "[BI", "genPad", "BI", &LibOrgBouncycastleCryptoTlsSSL3Mac_IPAD, &LibOrgBouncycastleCryptoTlsSSL3Mac_OPAD };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsSSL3Mac = { "SSL3Mac", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 10, 7, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsSSL3Mac;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoTlsSSL3Mac class]) {
    LibOrgBouncycastleCryptoTlsSSL3Mac_IPAD = LibOrgBouncycastleCryptoTlsSSL3Mac_genPadWithByte_withInt_(LibOrgBouncycastleCryptoTlsSSL3Mac_IPAD_BYTE, 48);
    LibOrgBouncycastleCryptoTlsSSL3Mac_OPAD = LibOrgBouncycastleCryptoTlsSSL3Mac_genPadWithByte_withInt_(LibOrgBouncycastleCryptoTlsSSL3Mac_OPAD_BYTE, 48);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoTlsSSL3Mac)
  }
}

@end

void LibOrgBouncycastleCryptoTlsSSL3Mac_initWithLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoTlsSSL3Mac *self, id<LibOrgBouncycastleCryptoDigest> digest) {
  NSObject_init(self);
  self->digest_ = digest;
  if ([((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest)) getDigestSize] == 20) {
    self->padLength_ = 40;
  }
  else {
    self->padLength_ = 48;
  }
}

LibOrgBouncycastleCryptoTlsSSL3Mac *new_LibOrgBouncycastleCryptoTlsSSL3Mac_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsSSL3Mac, initWithLibOrgBouncycastleCryptoDigest_, digest)
}

LibOrgBouncycastleCryptoTlsSSL3Mac *create_LibOrgBouncycastleCryptoTlsSSL3Mac_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsSSL3Mac, initWithLibOrgBouncycastleCryptoDigest_, digest)
}

IOSByteArray *LibOrgBouncycastleCryptoTlsSSL3Mac_genPadWithByte_withInt_(jbyte b, jint count) {
  LibOrgBouncycastleCryptoTlsSSL3Mac_initialize();
  IOSByteArray *padding = [IOSByteArray newArrayWithLength:count];
  LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(padding, b);
  return padding;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsSSL3Mac)
