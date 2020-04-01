//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/KeyedHashFunctions.java
//

#include "Digest.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyedHashFunctions.h"
#include "XMSSUtil.h"
#include "Xof.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/NullPointerException.h"

@interface LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions () {
 @public
  id<LibOrgBouncycastleCryptoDigest> digest_;
  jint digestSize_;
}

- (IOSByteArray *)coreDigestWithInt:(jint)fixedValue
                      withByteArray:(IOSByteArray *)key
                      withByteArray:(IOSByteArray *)index;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions, digest_, id<LibOrgBouncycastleCryptoDigest>)

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions_coreDigestWithInt_withByteArray_withByteArray_(LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions *self, jint fixedValue, IOSByteArray *key, IOSByteArray *index);

@implementation LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions

- (instancetype)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                               withInt:(jint)digestSize {
  LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions_initWithLibOrgBouncycastleCryptoDigest_withInt_(self, digest, digestSize);
  return self;
}

- (IOSByteArray *)coreDigestWithInt:(jint)fixedValue
                      withByteArray:(IOSByteArray *)key
                      withByteArray:(IOSByteArray *)index {
  return LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions_coreDigestWithInt_withByteArray_withByteArray_(self, fixedValue, key, index);
}

- (IOSByteArray *)FWithByteArray:(IOSByteArray *)key
                   withByteArray:(IOSByteArray *)inArg {
  if (((IOSByteArray *) nil_chk(key))->size_ != digestSize_) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"wrong key length");
  }
  if (((IOSByteArray *) nil_chk(inArg))->size_ != digestSize_) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"wrong in length");
  }
  return LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions_coreDigestWithInt_withByteArray_withByteArray_(self, 0, key, inArg);
}

- (IOSByteArray *)HWithByteArray:(IOSByteArray *)key
                   withByteArray:(IOSByteArray *)inArg {
  if (((IOSByteArray *) nil_chk(key))->size_ != digestSize_) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"wrong key length");
  }
  if (((IOSByteArray *) nil_chk(inArg))->size_ != (2 * digestSize_)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"wrong in length");
  }
  return LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions_coreDigestWithInt_withByteArray_withByteArray_(self, 1, key, inArg);
}

- (IOSByteArray *)HMsgWithByteArray:(IOSByteArray *)key
                      withByteArray:(IOSByteArray *)inArg {
  if (((IOSByteArray *) nil_chk(key))->size_ != (3 * digestSize_)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"wrong key length");
  }
  return LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions_coreDigestWithInt_withByteArray_withByteArray_(self, 2, key, inArg);
}

- (IOSByteArray *)PRFWithByteArray:(IOSByteArray *)key
                     withByteArray:(IOSByteArray *)address {
  if (((IOSByteArray *) nil_chk(key))->size_ != digestSize_) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"wrong key length");
  }
  if (((IOSByteArray *) nil_chk(address))->size_ != 32) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"wrong address length");
  }
  return LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions_coreDigestWithInt_withByteArray_withByteArray_(self, 3, key, address);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 1, 2, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, 3, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, 5, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, 6, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, 7, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoDigest:withInt:);
  methods[1].selector = @selector(coreDigestWithInt:withByteArray:withByteArray:);
  methods[2].selector = @selector(FWithByteArray:withByteArray:);
  methods[3].selector = @selector(HWithByteArray:withByteArray:);
  methods[4].selector = @selector(HMsgWithByteArray:withByteArray:);
  methods[5].selector = @selector(PRFWithByteArray:withByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "digest_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "digestSize_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigest;I", "coreDigest", "I[B[B", "F", "[B[B", "H", "HMsg", "PRF" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions = { "KeyedHashFunctions", "lib.org.bouncycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x10, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions;
}

@end

void LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions_initWithLibOrgBouncycastleCryptoDigest_withInt_(LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions *self, id<LibOrgBouncycastleCryptoDigest> digest, jint digestSize) {
  NSObject_init(self);
  if (digest == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"digest == null");
  }
  self->digest_ = digest;
  self->digestSize_ = digestSize;
}

LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions *new_LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions_initWithLibOrgBouncycastleCryptoDigest_withInt_(id<LibOrgBouncycastleCryptoDigest> digest, jint digestSize) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions, initWithLibOrgBouncycastleCryptoDigest_withInt_, digest, digestSize)
}

LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions *create_LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions_initWithLibOrgBouncycastleCryptoDigest_withInt_(id<LibOrgBouncycastleCryptoDigest> digest, jint digestSize) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions, initWithLibOrgBouncycastleCryptoDigest_withInt_, digest, digestSize)
}

IOSByteArray *LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions_coreDigestWithInt_withByteArray_withByteArray_(LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions *self, jint fixedValue, IOSByteArray *key, IOSByteArray *index) {
  IOSByteArray *in = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_toBytesBigEndianWithLong_withInt_(fixedValue, self->digestSize_);
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->digest_)) updateWithByteArray:in withInt:0 withInt:((IOSByteArray *) nil_chk(in))->size_];
  [self->digest_ updateWithByteArray:key withInt:0 withInt:((IOSByteArray *) nil_chk(key))->size_];
  [self->digest_ updateWithByteArray:index withInt:0 withInt:((IOSByteArray *) nil_chk(index))->size_];
  IOSByteArray *out = [IOSByteArray newArrayWithLength:self->digestSize_];
  if ([LibOrgBouncycastleCryptoXof_class_() isInstance:self->digest_]) {
    [((id<LibOrgBouncycastleCryptoXof>) cast_check(self->digest_, LibOrgBouncycastleCryptoXof_class_())) doFinalWithByteArray:out withInt:0 withInt:self->digestSize_];
  }
  else {
    [self->digest_ doFinalWithByteArray:out withInt:0];
  }
  return out;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions)