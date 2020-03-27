//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsNullCompression.java
//

#include "J2ObjC_source.h"
#include "TlsNullCompression.h"
#include "java/io/OutputStream.h"

@implementation LibOrgBouncycastleCryptoTlsTlsNullCompression

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsTlsNullCompression_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (JavaIoOutputStream *)compressWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  return output;
}

- (JavaIoOutputStream *)decompressWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  return output;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaIoOutputStream;", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaIoOutputStream;", 0x1, 2, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(compressWithJavaIoOutputStream:);
  methods[2].selector = @selector(decompressWithJavaIoOutputStream:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "compress", "LJavaIoOutputStream;", "decompress" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsTlsNullCompression = { "TlsNullCompression", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsTlsNullCompression;
}

@end

void LibOrgBouncycastleCryptoTlsTlsNullCompression_init(LibOrgBouncycastleCryptoTlsTlsNullCompression *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoTlsTlsNullCompression *new_LibOrgBouncycastleCryptoTlsTlsNullCompression_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsTlsNullCompression, init)
}

LibOrgBouncycastleCryptoTlsTlsNullCompression *create_LibOrgBouncycastleCryptoTlsTlsNullCompression_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsTlsNullCompression, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsTlsNullCompression)
