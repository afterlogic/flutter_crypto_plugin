//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/platform_stream/StreamCallback.java
//

#include "J2ObjC_source.h"
#include "StreamCallback.h"

@implementation LibComAfterlogicPgpPlatform_streamStreamCallback

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibComAfterlogicPgpPlatform_streamStreamCallback_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)invoke {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x401, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(invoke);
  #pragma clang diagnostic pop
  static const J2ObjcClassInfo _LibComAfterlogicPgpPlatform_streamStreamCallback = { "StreamCallback", "lib.com.afterlogic.pgp.platform_stream", NULL, methods, NULL, 7, 0x401, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpPlatform_streamStreamCallback;
}

@end

void LibComAfterlogicPgpPlatform_streamStreamCallback_init(LibComAfterlogicPgpPlatform_streamStreamCallback *self) {
  NSObject_init(self);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpPlatform_streamStreamCallback)