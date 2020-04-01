//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/newhope/Poly.java
//

#include "ChaCha20.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NTT.h"
#include "Pack.h"
#include "Params.h"
#include "Poly.h"
#include "Precomp.h"
#include "Reduce.h"
#include "SHAKEDigest.h"

@interface LibOrgBouncycastlePqcCryptoNewhopePoly ()

+ (jshort)normalizeWithShort:(jshort)x;

@end

__attribute__((unused)) static jshort LibOrgBouncycastlePqcCryptoNewhopePoly_normalizeWithShort_(jshort x);

@implementation LibOrgBouncycastlePqcCryptoNewhopePoly

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcCryptoNewhopePoly_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)addWithShortArray:(IOSShortArray *)x
           withShortArray:(IOSShortArray *)y
           withShortArray:(IOSShortArray *)z {
  LibOrgBouncycastlePqcCryptoNewhopePoly_addWithShortArray_withShortArray_withShortArray_(x, y, z);
}

+ (void)fromBytesWithShortArray:(IOSShortArray *)r
                  withByteArray:(IOSByteArray *)a {
  LibOrgBouncycastlePqcCryptoNewhopePoly_fromBytesWithShortArray_withByteArray_(r, a);
}

+ (void)fromNTTWithShortArray:(IOSShortArray *)r {
  LibOrgBouncycastlePqcCryptoNewhopePoly_fromNTTWithShortArray_(r);
}

+ (void)getNoiseWithShortArray:(IOSShortArray *)r
                 withByteArray:(IOSByteArray *)seed
                      withByte:(jbyte)nonce {
  LibOrgBouncycastlePqcCryptoNewhopePoly_getNoiseWithShortArray_withByteArray_withByte_(r, seed, nonce);
}

+ (void)pointWiseWithShortArray:(IOSShortArray *)x
                 withShortArray:(IOSShortArray *)y
                 withShortArray:(IOSShortArray *)z {
  LibOrgBouncycastlePqcCryptoNewhopePoly_pointWiseWithShortArray_withShortArray_withShortArray_(x, y, z);
}

+ (void)toBytesWithByteArray:(IOSByteArray *)r
              withShortArray:(IOSShortArray *)p {
  LibOrgBouncycastlePqcCryptoNewhopePoly_toBytesWithByteArray_withShortArray_(r, p);
}

+ (void)toNTTWithShortArray:(IOSShortArray *)r {
  LibOrgBouncycastlePqcCryptoNewhopePoly_toNTTWithShortArray_(r);
}

+ (void)uniformWithShortArray:(IOSShortArray *)a
                withByteArray:(IOSByteArray *)seed {
  LibOrgBouncycastlePqcCryptoNewhopePoly_uniformWithShortArray_withByteArray_(a, seed);
}

+ (jshort)normalizeWithShort:(jshort)x {
  return LibOrgBouncycastlePqcCryptoNewhopePoly_normalizeWithShort_(x);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 8, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 9, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 11, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 12, 3, -1, -1, -1, -1 },
    { NULL, "S", 0xa, 13, 14, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(addWithShortArray:withShortArray:withShortArray:);
  methods[2].selector = @selector(fromBytesWithShortArray:withByteArray:);
  methods[3].selector = @selector(fromNTTWithShortArray:);
  methods[4].selector = @selector(getNoiseWithShortArray:withByteArray:withByte:);
  methods[5].selector = @selector(pointWiseWithShortArray:withShortArray:withShortArray:);
  methods[6].selector = @selector(toBytesWithByteArray:withShortArray:);
  methods[7].selector = @selector(toNTTWithShortArray:);
  methods[8].selector = @selector(uniformWithShortArray:withByteArray:);
  methods[9].selector = @selector(normalizeWithShort:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "add", "[S[S[S", "fromBytes", "[S[B", "fromNTT", "[S", "getNoise", "[S[BB", "pointWise", "toBytes", "[B[S", "toNTT", "uniform", "normalize", "S" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoNewhopePoly = { "Poly", "lib.org.bouncycastle.pqc.crypto.newhope", ptrTable, methods, NULL, 7, 0x0, 10, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoNewhopePoly;
}

@end

void LibOrgBouncycastlePqcCryptoNewhopePoly_init(LibOrgBouncycastlePqcCryptoNewhopePoly *self) {
  NSObject_init(self);
}

LibOrgBouncycastlePqcCryptoNewhopePoly *new_LibOrgBouncycastlePqcCryptoNewhopePoly_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoNewhopePoly, init)
}

LibOrgBouncycastlePqcCryptoNewhopePoly *create_LibOrgBouncycastlePqcCryptoNewhopePoly_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoNewhopePoly, init)
}

void LibOrgBouncycastlePqcCryptoNewhopePoly_addWithShortArray_withShortArray_withShortArray_(IOSShortArray *x, IOSShortArray *y, IOSShortArray *z) {
  LibOrgBouncycastlePqcCryptoNewhopePoly_initialize();
  for (jint i = 0; i < LibOrgBouncycastlePqcCryptoNewhopeParams_N; ++i) {
    *IOSShortArray_GetRef(nil_chk(z), i) = LibOrgBouncycastlePqcCryptoNewhopeReduce_barrettWithShort_((jshort) (IOSShortArray_Get(nil_chk(x), i) + IOSShortArray_Get(nil_chk(y), i)));
  }
}

void LibOrgBouncycastlePqcCryptoNewhopePoly_fromBytesWithShortArray_withByteArray_(IOSShortArray *r, IOSByteArray *a) {
  LibOrgBouncycastlePqcCryptoNewhopePoly_initialize();
  for (jint i = 0; i < LibOrgBouncycastlePqcCryptoNewhopeParams_N / 4; ++i) {
    jint j = 7 * i;
    jint a0 = IOSByteArray_Get(nil_chk(a), j + 0) & (jint) 0xFF;
    jint a1 = IOSByteArray_Get(a, j + 1) & (jint) 0xFF;
    jint a2 = IOSByteArray_Get(a, j + 2) & (jint) 0xFF;
    jint a3 = IOSByteArray_Get(a, j + 3) & (jint) 0xFF;
    jint a4 = IOSByteArray_Get(a, j + 4) & (jint) 0xFF;
    jint a5 = IOSByteArray_Get(a, j + 5) & (jint) 0xFF;
    jint a6 = IOSByteArray_Get(a, j + 6) & (jint) 0xFF;
    jint k = 4 * i;
    *IOSShortArray_GetRef(nil_chk(r), k + 0) = (jshort) (a0 | (JreLShift32((a1 & (jint) 0x3F), 8)));
    *IOSShortArray_GetRef(r, k + 1) = (jshort) ((JreURShift32(a1, 6)) | (JreLShift32(a2, 2)) | (JreLShift32((a3 & (jint) 0x0F), 10)));
    *IOSShortArray_GetRef(r, k + 2) = (jshort) ((JreURShift32(a3, 4)) | (JreLShift32(a4, 4)) | (JreLShift32((a5 & (jint) 0x03), 12)));
    *IOSShortArray_GetRef(r, k + 3) = (jshort) ((JreURShift32(a5, 2)) | (JreLShift32(a6, 6)));
  }
}

void LibOrgBouncycastlePqcCryptoNewhopePoly_fromNTTWithShortArray_(IOSShortArray *r) {
  LibOrgBouncycastlePqcCryptoNewhopePoly_initialize();
  LibOrgBouncycastlePqcCryptoNewhopeNTT_bitReverseWithShortArray_(r);
  LibOrgBouncycastlePqcCryptoNewhopeNTT_coreWithShortArray_withShortArray_(r, JreLoadStatic(LibOrgBouncycastlePqcCryptoNewhopePrecomp, OMEGAS_INV_MONTGOMERY));
  LibOrgBouncycastlePqcCryptoNewhopeNTT_mulCoefficientsWithShortArray_withShortArray_(r, JreLoadStatic(LibOrgBouncycastlePqcCryptoNewhopePrecomp, PSIS_INV_MONTGOMERY));
}

void LibOrgBouncycastlePqcCryptoNewhopePoly_getNoiseWithShortArray_withByteArray_withByte_(IOSShortArray *r, IOSByteArray *seed, jbyte nonce) {
  LibOrgBouncycastlePqcCryptoNewhopePoly_initialize();
  IOSByteArray *iv = [IOSByteArray newArrayWithLength:8];
  *IOSByteArray_GetRef(iv, 0) = nonce;
  IOSByteArray *buf = [IOSByteArray newArrayWithLength:4 * LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopeChaCha20_processWithByteArray_withByteArray_withByteArray_withInt_withInt_(seed, iv, buf, 0, buf->size_);
  for (jint i = 0; i < LibOrgBouncycastlePqcCryptoNewhopeParams_N; ++i) {
    jint t = LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(buf, i * 4);
    jint d = 0;
    for (jint j = 0; j < 8; ++j) {
      d += (JreRShift32(t, j)) & (jint) 0x01010101;
    }
    jint a = ((JreURShift32(d, 24)) + (JreURShift32(d, 0))) & (jint) 0xFF;
    jint b = ((JreURShift32(d, 16)) + (JreURShift32(d, 8))) & (jint) 0xFF;
    *IOSShortArray_GetRef(nil_chk(r), i) = (jshort) (a + LibOrgBouncycastlePqcCryptoNewhopeParams_Q - b);
  }
}

void LibOrgBouncycastlePqcCryptoNewhopePoly_pointWiseWithShortArray_withShortArray_withShortArray_(IOSShortArray *x, IOSShortArray *y, IOSShortArray *z) {
  LibOrgBouncycastlePqcCryptoNewhopePoly_initialize();
  for (jint i = 0; i < LibOrgBouncycastlePqcCryptoNewhopeParams_N; ++i) {
    jint xi = IOSShortArray_Get(nil_chk(x), i) & (jint) 0xFFFF;
    jint yi = IOSShortArray_Get(nil_chk(y), i) & (jint) 0xFFFF;
    jshort t = LibOrgBouncycastlePqcCryptoNewhopeReduce_montgomeryWithInt_(3186 * yi);
    *IOSShortArray_GetRef(nil_chk(z), i) = LibOrgBouncycastlePqcCryptoNewhopeReduce_montgomeryWithInt_(xi * (t & (jint) 0xFFFF));
  }
}

void LibOrgBouncycastlePqcCryptoNewhopePoly_toBytesWithByteArray_withShortArray_(IOSByteArray *r, IOSShortArray *p) {
  LibOrgBouncycastlePqcCryptoNewhopePoly_initialize();
  for (jint i = 0; i < LibOrgBouncycastlePqcCryptoNewhopeParams_N / 4; ++i) {
    jint j = 4 * i;
    jshort t0 = LibOrgBouncycastlePqcCryptoNewhopePoly_normalizeWithShort_(IOSShortArray_Get(nil_chk(p), j + 0));
    jshort t1 = LibOrgBouncycastlePqcCryptoNewhopePoly_normalizeWithShort_(IOSShortArray_Get(p, j + 1));
    jshort t2 = LibOrgBouncycastlePqcCryptoNewhopePoly_normalizeWithShort_(IOSShortArray_Get(p, j + 2));
    jshort t3 = LibOrgBouncycastlePqcCryptoNewhopePoly_normalizeWithShort_(IOSShortArray_Get(p, j + 3));
    jint k = 7 * i;
    *IOSByteArray_GetRef(nil_chk(r), k + 0) = (jbyte) t0;
    *IOSByteArray_GetRef(r, k + 1) = (jbyte) ((JreRShift32(t0, 8)) | (JreLShift32(t1, 6)));
    *IOSByteArray_GetRef(r, k + 2) = (jbyte) (JreRShift32(t1, 2));
    *IOSByteArray_GetRef(r, k + 3) = (jbyte) ((JreRShift32(t1, 10)) | (JreLShift32(t2, 4)));
    *IOSByteArray_GetRef(r, k + 4) = (jbyte) (JreRShift32(t2, 4));
    *IOSByteArray_GetRef(r, k + 5) = (jbyte) ((JreRShift32(t2, 12)) | (JreLShift32(t3, 2)));
    *IOSByteArray_GetRef(r, k + 6) = (jbyte) (JreRShift32(t3, 6));
  }
}

void LibOrgBouncycastlePqcCryptoNewhopePoly_toNTTWithShortArray_(IOSShortArray *r) {
  LibOrgBouncycastlePqcCryptoNewhopePoly_initialize();
  LibOrgBouncycastlePqcCryptoNewhopeNTT_mulCoefficientsWithShortArray_withShortArray_(r, JreLoadStatic(LibOrgBouncycastlePqcCryptoNewhopePrecomp, PSIS_BITREV_MONTGOMERY));
  LibOrgBouncycastlePqcCryptoNewhopeNTT_coreWithShortArray_withShortArray_(r, JreLoadStatic(LibOrgBouncycastlePqcCryptoNewhopePrecomp, OMEGAS_MONTGOMERY));
}

void LibOrgBouncycastlePqcCryptoNewhopePoly_uniformWithShortArray_withByteArray_(IOSShortArray *a, IOSByteArray *seed) {
  LibOrgBouncycastlePqcCryptoNewhopePoly_initialize();
  LibOrgBouncycastleCryptoDigestsSHAKEDigest *xof = new_LibOrgBouncycastleCryptoDigestsSHAKEDigest_initWithInt_(128);
  [xof updateWithByteArray:seed withInt:0 withInt:((IOSByteArray *) nil_chk(seed))->size_];
  jint pos = 0;
  for (; ; ) {
    IOSByteArray *output = [IOSByteArray newArrayWithLength:256];
    [xof doOutputWithByteArray:output withInt:0 withInt:output->size_];
    for (jint i = 0; i < output->size_; i += 2) {
      jint val = (IOSByteArray_Get(output, i) & (jint) 0xFF) | (JreLShift32((IOSByteArray_Get(output, i + 1) & (jint) 0xFF), 8));
      if (val < 5 * LibOrgBouncycastlePqcCryptoNewhopeParams_Q) {
        *IOSShortArray_GetRef(nil_chk(a), pos++) = (jshort) val;
        if (pos == LibOrgBouncycastlePqcCryptoNewhopeParams_N) {
          return;
        }
      }
    }
  }
}

jshort LibOrgBouncycastlePqcCryptoNewhopePoly_normalizeWithShort_(jshort x) {
  LibOrgBouncycastlePqcCryptoNewhopePoly_initialize();
  jint t = LibOrgBouncycastlePqcCryptoNewhopeReduce_barrettWithShort_(x);
  jint m = t - LibOrgBouncycastlePqcCryptoNewhopeParams_Q;
  jint c = JreRShift32(m, 31);
  t = m ^ ((t ^ m) & c);
  return (jshort) t;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoNewhopePoly)