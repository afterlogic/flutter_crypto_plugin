//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/ntru/NTRUSignerPrng.java
//

#include "Digest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NTRUSignerPrng.h"
#include "java/nio/ByteBuffer.h"

@interface LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng () {
 @public
  jint counter_;
  IOSByteArray *seed_;
  id<LibOrgBouncycastleCryptoDigest> hashAlg_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng, seed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng, hashAlg_, id<LibOrgBouncycastleCryptoDigest>)

@implementation LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng

- (instancetype)initWithByteArray:(IOSByteArray *)seed
withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)hashAlg {
  LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng_initWithByteArray_withLibOrgBouncycastleCryptoDigest_(self, seed, hashAlg);
  return self;
}

- (IOSByteArray *)nextBytesWithInt:(jint)n {
  JavaNioByteBuffer *buf = JavaNioByteBuffer_allocateWithInt_(n);
  while ([((JavaNioByteBuffer *) nil_chk(buf)) hasRemaining]) {
    JavaNioByteBuffer *cbuf = JavaNioByteBuffer_allocateWithInt_(((IOSByteArray *) nil_chk(seed_))->size_ + 4);
    (void) [((JavaNioByteBuffer *) nil_chk(cbuf)) putWithByteArray:seed_];
    (void) [cbuf putIntWithInt:counter_];
    IOSByteArray *array = [cbuf array];
    IOSByteArray *hash_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(hashAlg_)) getDigestSize]];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(hashAlg_)) updateWithByteArray:array withInt:0 withInt:((IOSByteArray *) nil_chk(array))->size_];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(hashAlg_)) doFinalWithByteArray:hash_ withInt:0];
    if ([buf remaining] < hash_->size_) {
      (void) [buf putWithByteArray:hash_ withInt:0 withInt:[buf remaining]];
    }
    else {
      (void) [buf putWithByteArray:hash_];
    }
    counter_++;
  }
  return [buf array];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x0, 1, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:withLibOrgBouncycastleCryptoDigest:);
  methods[1].selector = @selector(nextBytesWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "counter_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "seed_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hashAlg_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[BLLibOrgBouncycastleCryptoDigest;", "nextBytes", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng = { "NTRUSignerPrng", "lib.org.bouncycastle.pqc.crypto.ntru", ptrTable, methods, fields, 7, 0x1, 2, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng;
}

@end

void LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng_initWithByteArray_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng *self, IOSByteArray *seed, id<LibOrgBouncycastleCryptoDigest> hashAlg) {
  NSObject_init(self);
  self->counter_ = 0;
  self->seed_ = seed;
  self->hashAlg_ = hashAlg;
}

LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng *new_LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng_initWithByteArray_withLibOrgBouncycastleCryptoDigest_(IOSByteArray *seed, id<LibOrgBouncycastleCryptoDigest> hashAlg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng, initWithByteArray_withLibOrgBouncycastleCryptoDigest_, seed, hashAlg)
}

LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng *create_LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng_initWithByteArray_withLibOrgBouncycastleCryptoDigest_(IOSByteArray *seed, id<LibOrgBouncycastleCryptoDigest> hashAlg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng, initWithByteArray_withLibOrgBouncycastleCryptoDigest_, seed, hashAlg)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng)
