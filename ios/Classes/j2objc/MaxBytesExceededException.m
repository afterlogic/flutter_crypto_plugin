//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/MaxBytesExceededException.java
//

#include "J2ObjC_source.h"
#include "MaxBytesExceededException.h"
#include "RuntimeCryptoException.h"

@implementation LibOrgBouncycastleCryptoMaxBytesExceededException

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoMaxBytesExceededException_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithNSString:(NSString *)message {
  LibOrgBouncycastleCryptoMaxBytesExceededException_initWithNSString_(self, message);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithNSString:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LNSString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoMaxBytesExceededException = { "MaxBytesExceededException", "lib.org.bouncycastle.crypto", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoMaxBytesExceededException;
}

@end

void LibOrgBouncycastleCryptoMaxBytesExceededException_init(LibOrgBouncycastleCryptoMaxBytesExceededException *self) {
  LibOrgBouncycastleCryptoRuntimeCryptoException_init(self);
}

LibOrgBouncycastleCryptoMaxBytesExceededException *new_LibOrgBouncycastleCryptoMaxBytesExceededException_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoMaxBytesExceededException, init)
}

LibOrgBouncycastleCryptoMaxBytesExceededException *create_LibOrgBouncycastleCryptoMaxBytesExceededException_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoMaxBytesExceededException, init)
}

void LibOrgBouncycastleCryptoMaxBytesExceededException_initWithNSString_(LibOrgBouncycastleCryptoMaxBytesExceededException *self, NSString *message) {
  LibOrgBouncycastleCryptoRuntimeCryptoException_initWithNSString_(self, message);
}

LibOrgBouncycastleCryptoMaxBytesExceededException *new_LibOrgBouncycastleCryptoMaxBytesExceededException_initWithNSString_(NSString *message) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoMaxBytesExceededException, initWithNSString_, message)
}

LibOrgBouncycastleCryptoMaxBytesExceededException *create_LibOrgBouncycastleCryptoMaxBytesExceededException_initWithNSString_(NSString *message) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoMaxBytesExceededException, initWithNSString_, message)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoMaxBytesExceededException)
