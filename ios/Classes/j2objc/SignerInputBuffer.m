//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/SignerInputBuffer.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Signer.h"
#include "SignerInputBuffer.h"
#include "java/io/ByteArrayOutputStream.h"

@implementation LibOrgBouncycastleCryptoTlsSignerInputBuffer

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsSignerInputBuffer_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)updateSignerWithLibOrgBouncycastleCryptoSigner:(id<LibOrgBouncycastleCryptoSigner>)s {
  [((id<LibOrgBouncycastleCryptoSigner>) nil_chk(s)) updateWithByteArray:self->buf_ withInt:0 withInt:count_];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(updateSignerWithLibOrgBouncycastleCryptoSigner:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "updateSigner", "LLibOrgBouncycastleCryptoSigner;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsSignerInputBuffer = { "SignerInputBuffer", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, NULL, 7, 0x0, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsSignerInputBuffer;
}

@end

void LibOrgBouncycastleCryptoTlsSignerInputBuffer_init(LibOrgBouncycastleCryptoTlsSignerInputBuffer *self) {
  JavaIoByteArrayOutputStream_init(self);
}

LibOrgBouncycastleCryptoTlsSignerInputBuffer *new_LibOrgBouncycastleCryptoTlsSignerInputBuffer_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsSignerInputBuffer, init)
}

LibOrgBouncycastleCryptoTlsSignerInputBuffer *create_LibOrgBouncycastleCryptoTlsSignerInputBuffer_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsSignerInputBuffer, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsSignerInputBuffer)
