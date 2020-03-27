//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/bc/SignerOutputStream.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Signer.h"
#include "SignerOutputStream.h"
#include "java/io/OutputStream.h"

@interface LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream () {
 @public
  id<LibOrgBouncycastleCryptoSigner> sig_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream, sig_, id<LibOrgBouncycastleCryptoSigner>)

@implementation LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream

- (instancetype)initWithLibOrgBouncycastleCryptoSigner:(id<LibOrgBouncycastleCryptoSigner>)sig {
  LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream_initWithLibOrgBouncycastleCryptoSigner_(self, sig);
  return self;
}

- (void)writeWithByteArray:(IOSByteArray *)bytes
                   withInt:(jint)off
                   withInt:(jint)len {
  [((id<LibOrgBouncycastleCryptoSigner>) nil_chk(sig_)) updateWithByteArray:bytes withInt:off withInt:len];
}

- (void)writeWithByteArray:(IOSByteArray *)bytes {
  [((id<LibOrgBouncycastleCryptoSigner>) nil_chk(sig_)) updateWithByteArray:bytes withInt:0 withInt:((IOSByteArray *) nil_chk(bytes))->size_];
}

- (void)writeWithInt:(jint)b {
  [((id<LibOrgBouncycastleCryptoSigner>) nil_chk(sig_)) updateWithByte:(jbyte) b];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 4, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 5, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoSigner:);
  methods[1].selector = @selector(writeWithByteArray:withInt:withInt:);
  methods[2].selector = @selector(writeWithByteArray:);
  methods[3].selector = @selector(writeWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "sig_", "LLibOrgBouncycastleCryptoSigner;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoSigner;", "write", "[BII", "LJavaIoIOException;", "[B", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream = { "SignerOutputStream", "lib.org.bouncycastle.openpgp.operator.bc", ptrTable, methods, fields, 7, 0x0, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream;
}

@end

void LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream_initWithLibOrgBouncycastleCryptoSigner_(LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream *self, id<LibOrgBouncycastleCryptoSigner> sig) {
  JavaIoOutputStream_init(self);
  self->sig_ = sig;
}

LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream *new_LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream_initWithLibOrgBouncycastleCryptoSigner_(id<LibOrgBouncycastleCryptoSigner> sig) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream, initWithLibOrgBouncycastleCryptoSigner_, sig)
}

LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream *create_LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream_initWithLibOrgBouncycastleCryptoSigner_(id<LibOrgBouncycastleCryptoSigner> sig) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream, initWithLibOrgBouncycastleCryptoSigner_, sig)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorBcSignerOutputStream)
