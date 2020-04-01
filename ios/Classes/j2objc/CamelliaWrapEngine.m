//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/CamelliaWrapEngine.java
//

#include "CamelliaEngine.h"
#include "CamelliaWrapEngine.h"
#include "J2ObjC_source.h"
#include "RFC3394WrapEngine.h"

@implementation LibOrgBouncycastleCryptoEnginesCamelliaWrapEngine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoEnginesCamelliaWrapEngine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesCamelliaWrapEngine = { "CamelliaWrapEngine", "lib.org.bouncycastle.crypto.engines", NULL, methods, NULL, 7, 0x1, 1, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesCamelliaWrapEngine;
}

@end

void LibOrgBouncycastleCryptoEnginesCamelliaWrapEngine_init(LibOrgBouncycastleCryptoEnginesCamelliaWrapEngine *self) {
  LibOrgBouncycastleCryptoEnginesRFC3394WrapEngine_initWithLibOrgBouncycastleCryptoBlockCipher_(self, new_LibOrgBouncycastleCryptoEnginesCamelliaEngine_init());
}

LibOrgBouncycastleCryptoEnginesCamelliaWrapEngine *new_LibOrgBouncycastleCryptoEnginesCamelliaWrapEngine_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesCamelliaWrapEngine, init)
}

LibOrgBouncycastleCryptoEnginesCamelliaWrapEngine *create_LibOrgBouncycastleCryptoEnginesCamelliaWrapEngine_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesCamelliaWrapEngine, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesCamelliaWrapEngine)