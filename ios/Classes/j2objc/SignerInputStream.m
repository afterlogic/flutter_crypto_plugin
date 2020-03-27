//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/io/SignerInputStream.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Signer.h"
#include "SignerInputStream.h"
#include "java/io/FilterInputStream.h"
#include "java/io/InputStream.h"

@implementation LibOrgBouncycastleCryptoIoSignerInputStream

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)stream
       withLibOrgBouncycastleCryptoSigner:(id<LibOrgBouncycastleCryptoSigner>)signer {
  LibOrgBouncycastleCryptoIoSignerInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoSigner_(self, stream, signer);
  return self;
}

- (jint)read {
  jint b = [((JavaIoInputStream *) nil_chk(JreLoadVolatileId(&in_))) read];
  if (b >= 0) {
    [((id<LibOrgBouncycastleCryptoSigner>) nil_chk(signer_)) updateWithByte:(jbyte) b];
  }
  return b;
}

- (jint)readWithByteArray:(IOSByteArray *)b
                  withInt:(jint)off
                  withInt:(jint)len {
  jint n = [((JavaIoInputStream *) nil_chk(JreLoadVolatileId(&in_))) readWithByteArray:b withInt:off withInt:len];
  if (n > 0) {
    [((id<LibOrgBouncycastleCryptoSigner>) nil_chk(signer_)) updateWithByteArray:b withInt:off withInt:n];
  }
  return n;
}

- (id<LibOrgBouncycastleCryptoSigner>)getSigner {
  return signer_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 3, 1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoSigner;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoInputStream:withLibOrgBouncycastleCryptoSigner:);
  methods[1].selector = @selector(read);
  methods[2].selector = @selector(readWithByteArray:withInt:withInt:);
  methods[3].selector = @selector(getSigner);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "signer_", "LLibOrgBouncycastleCryptoSigner;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoInputStream;LLibOrgBouncycastleCryptoSigner;", "LJavaIoIOException;", "read", "[BII" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoIoSignerInputStream = { "SignerInputStream", "lib.org.bouncycastle.crypto.io", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoIoSignerInputStream;
}

@end

void LibOrgBouncycastleCryptoIoSignerInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoSigner_(LibOrgBouncycastleCryptoIoSignerInputStream *self, JavaIoInputStream *stream, id<LibOrgBouncycastleCryptoSigner> signer) {
  JavaIoFilterInputStream_initWithJavaIoInputStream_(self, stream);
  self->signer_ = signer;
}

LibOrgBouncycastleCryptoIoSignerInputStream *new_LibOrgBouncycastleCryptoIoSignerInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoSigner_(JavaIoInputStream *stream, id<LibOrgBouncycastleCryptoSigner> signer) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoIoSignerInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoSigner_, stream, signer)
}

LibOrgBouncycastleCryptoIoSignerInputStream *create_LibOrgBouncycastleCryptoIoSignerInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleCryptoSigner_(JavaIoInputStream *stream, id<LibOrgBouncycastleCryptoSigner> signer) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoIoSignerInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleCryptoSigner_, stream, signer)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoIoSignerInputStream)
