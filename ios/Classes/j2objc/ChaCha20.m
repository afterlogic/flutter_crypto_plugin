//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/newhope/ChaCha20.java
//

#include "ChaCha20.h"
#include "ChaChaEngine.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "ParametersWithIV.h"

@implementation LibOrgBouncycastlePqcCryptoNewhopeChaCha20

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcCryptoNewhopeChaCha20_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)processWithByteArray:(IOSByteArray *)key
               withByteArray:(IOSByteArray *)nonce
               withByteArray:(IOSByteArray *)buf
                     withInt:(jint)off
                     withInt:(jint)len {
  LibOrgBouncycastlePqcCryptoNewhopeChaCha20_processWithByteArray_withByteArray_withByteArray_withInt_withInt_(key, nonce, buf, off, len);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(processWithByteArray:withByteArray:withByteArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "process", "[B[B[BII" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoNewhopeChaCha20 = { "ChaCha20", "lib.org.bouncycastle.pqc.crypto.newhope", ptrTable, methods, NULL, 7, 0x0, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoNewhopeChaCha20;
}

@end

void LibOrgBouncycastlePqcCryptoNewhopeChaCha20_init(LibOrgBouncycastlePqcCryptoNewhopeChaCha20 *self) {
  NSObject_init(self);
}

LibOrgBouncycastlePqcCryptoNewhopeChaCha20 *new_LibOrgBouncycastlePqcCryptoNewhopeChaCha20_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoNewhopeChaCha20, init)
}

LibOrgBouncycastlePqcCryptoNewhopeChaCha20 *create_LibOrgBouncycastlePqcCryptoNewhopeChaCha20_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoNewhopeChaCha20, init)
}

void LibOrgBouncycastlePqcCryptoNewhopeChaCha20_processWithByteArray_withByteArray_withByteArray_withInt_withInt_(IOSByteArray *key, IOSByteArray *nonce, IOSByteArray *buf, jint off, jint len) {
  LibOrgBouncycastlePqcCryptoNewhopeChaCha20_initialize();
  LibOrgBouncycastleCryptoEnginesChaChaEngine *e = new_LibOrgBouncycastleCryptoEnginesChaChaEngine_initWithInt_(20);
  [e init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_(key), nonce)];
  [e processBytesWithByteArray:buf withInt:off withInt:len withByteArray:buf withInt:off];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoNewhopeChaCha20)
