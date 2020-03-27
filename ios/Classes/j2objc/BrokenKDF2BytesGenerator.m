//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/BrokenKDF2BytesGenerator.java
//

#include "BrokenKDF2BytesGenerator.h"
#include "DerivationParameters.h"
#include "Digest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KDFParameters.h"
#include "OutputLengthException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator () {
 @public
  id<LibOrgBouncycastleCryptoDigest> digest_;
  IOSByteArray *shared_;
  IOSByteArray *iv_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator, digest_, id<LibOrgBouncycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator, shared_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator, iv_, IOSByteArray *)

@implementation LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator

- (instancetype)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest {
  LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator_initWithLibOrgBouncycastleCryptoDigest_(self, digest);
  return self;
}

- (void)init__WithLibOrgBouncycastleCryptoDerivationParameters:(id<LibOrgBouncycastleCryptoDerivationParameters>)param {
  if (!([param isKindOfClass:[LibOrgBouncycastleCryptoParamsKDFParameters class]])) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"KDF parameters required for generator");
  }
  LibOrgBouncycastleCryptoParamsKDFParameters *p = (LibOrgBouncycastleCryptoParamsKDFParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsKDFParameters class]);
  shared_ = [((LibOrgBouncycastleCryptoParamsKDFParameters *) nil_chk(p)) getSharedSecret];
  iv_ = [p getIV];
}

- (id<LibOrgBouncycastleCryptoDigest>)getDigest {
  return digest_;
}

- (jint)generateBytesWithByteArray:(IOSByteArray *)outArg
                           withInt:(jint)outOff
                           withInt:(jint)len {
  if ((((IOSByteArray *) nil_chk(outArg))->size_ - len) < outOff) {
    @throw new_LibOrgBouncycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too small");
  }
  jlong oBits = len * 8LL;
  if (oBits > ([((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize] * 8LL * (JreLShift64(1LL, 32 - 1)))) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Output length too large");
  }
  jint cThreshold = (jint) (oBits / [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize]);
  IOSByteArray *dig = nil;
  dig = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize]];
  for (jint counter = 1; counter <= cThreshold; counter++) {
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:shared_ withInt:0 withInt:((IOSByteArray *) nil_chk(shared_))->size_];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByte:(jbyte) (counter & (jint) 0xff)];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByte:(jbyte) ((JreRShift32(counter, 8)) & (jint) 0xff)];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByte:(jbyte) ((JreRShift32(counter, 16)) & (jint) 0xff)];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByte:(jbyte) ((JreRShift32(counter, 24)) & (jint) 0xff)];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:iv_ withInt:0 withInt:((IOSByteArray *) nil_chk(iv_))->size_];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:dig withInt:0];
    if ((len - outOff) > dig->size_) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(dig, 0, outArg, outOff, dig->size_);
      outOff += dig->size_;
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(dig, 0, outArg, outOff, len - outOff);
    }
  }
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) reset];
  return len;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoDigest;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, 4, 5, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoDigest:);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoDerivationParameters:);
  methods[2].selector = @selector(getDigest);
  methods[3].selector = @selector(generateBytesWithByteArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "digest_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "shared_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "iv_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigest;", "init", "LLibOrgBouncycastleCryptoDerivationParameters;", "generateBytes", "[BII", "LLibOrgBouncycastleCryptoDataLengthException;LJavaLangIllegalArgumentException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator = { "BrokenKDF2BytesGenerator", "lib.org.bouncycastle.jce.provider", ptrTable, methods, fields, 7, 0x1, 4, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator;
}

@end

void LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator_initWithLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator *self, id<LibOrgBouncycastleCryptoDigest> digest) {
  NSObject_init(self);
  self->digest_ = digest;
}

LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator *new_LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator, initWithLibOrgBouncycastleCryptoDigest_, digest)
}

LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator *create_LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator, initWithLibOrgBouncycastleCryptoDigest_, digest)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceProviderBrokenKDF2BytesGenerator)