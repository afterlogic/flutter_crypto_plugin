//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/io/StreamOverflowException.java
//

#include "J2ObjC_source.h"
#include "StreamOverflowException.h"
#include "java/io/IOException.h"

@implementation LibOrgBouncycastleUtilIoStreamOverflowException

- (instancetype)initWithNSString:(NSString *)msg {
  LibOrgBouncycastleUtilIoStreamOverflowException_initWithNSString_(self, msg);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LNSString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilIoStreamOverflowException = { "StreamOverflowException", "lib.org.bouncycastle.util.io", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilIoStreamOverflowException;
}

@end

void LibOrgBouncycastleUtilIoStreamOverflowException_initWithNSString_(LibOrgBouncycastleUtilIoStreamOverflowException *self, NSString *msg) {
  JavaIoIOException_initWithNSString_(self, msg);
}

LibOrgBouncycastleUtilIoStreamOverflowException *new_LibOrgBouncycastleUtilIoStreamOverflowException_initWithNSString_(NSString *msg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilIoStreamOverflowException, initWithNSString_, msg)
}

LibOrgBouncycastleUtilIoStreamOverflowException *create_LibOrgBouncycastleUtilIoStreamOverflowException_initWithNSString_(NSString *msg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilIoStreamOverflowException, initWithNSString_, msg)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilIoStreamOverflowException)
