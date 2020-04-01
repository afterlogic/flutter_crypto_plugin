//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/prng/ThreadedSeedGenerator.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ThreadedSeedGenerator.h"
#include "java/lang/InterruptedException.h"
#include "java/lang/Runnable.h"
#include "java/lang/Thread.h"

@interface LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator : NSObject < JavaLangRunnable > {
 @public
  volatile_jint counter_;
  volatile_jboolean stop_;
}

- (instancetype)initWithLibOrgBouncycastleCryptoPrngThreadedSeedGenerator:(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator *)outer$;

- (void)run;

- (IOSByteArray *)generateSeedWithInt:(jint)numbytes
                          withBoolean:(jboolean)fast;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator)

__attribute__((unused)) static void LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator_initWithLibOrgBouncycastleCryptoPrngThreadedSeedGenerator_(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator *self, LibOrgBouncycastleCryptoPrngThreadedSeedGenerator *outer$);

__attribute__((unused)) static LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator *new_LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator_initWithLibOrgBouncycastleCryptoPrngThreadedSeedGenerator_(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator *outer$) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator *create_LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator_initWithLibOrgBouncycastleCryptoPrngThreadedSeedGenerator_(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator *outer$);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator)

@implementation LibOrgBouncycastleCryptoPrngThreadedSeedGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)generateSeedWithInt:(jint)numBytes
                          withBoolean:(jboolean)fast {
  LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator *gen = new_LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator_initWithLibOrgBouncycastleCryptoPrngThreadedSeedGenerator_(self);
  return [gen generateSeedWithInt:numBytes withBoolean:fast];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generateSeedWithInt:withBoolean:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "generateSeed", "IZ", "LLibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoPrngThreadedSeedGenerator = { "ThreadedSeedGenerator", "lib.org.bouncycastle.crypto.prng", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, 2, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoPrngThreadedSeedGenerator;
}

@end

void LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_init(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoPrngThreadedSeedGenerator *new_LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator, init)
}

LibOrgBouncycastleCryptoPrngThreadedSeedGenerator *create_LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator)

@implementation LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator

- (instancetype)initWithLibOrgBouncycastleCryptoPrngThreadedSeedGenerator:(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator *)outer$ {
  LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator_initWithLibOrgBouncycastleCryptoPrngThreadedSeedGenerator_(self, outer$);
  return self;
}

- (void)run {
  while (!JreLoadVolatileBoolean(&self->stop_)) {
    self->counter_++;
  }
}

- (IOSByteArray *)generateSeedWithInt:(jint)numbytes
                          withBoolean:(jboolean)fast {
  JavaLangThread *t = new_JavaLangThread_initWithJavaLangRunnable_(self);
  IOSByteArray *result = [IOSByteArray newArrayWithLength:numbytes];
  JreAssignVolatileInt(&self->counter_, 0);
  JreAssignVolatileBoolean(&self->stop_, false);
  jint last = 0;
  jint end;
  [t start];
  if (fast) {
    end = numbytes;
  }
  else {
    end = numbytes * 8;
  }
  for (jint i = 0; i < end; i++) {
    while (JreLoadVolatileInt(&self->counter_) == last) {
      @try {
        JavaLangThread_sleepWithLong_(1);
      }
      @catch (JavaLangInterruptedException *e) {
      }
    }
    last = JreLoadVolatileInt(&self->counter_);
    if (fast) {
      *IOSByteArray_GetRef(result, i) = (jbyte) (last & (jint) 0xff);
    }
    else {
      jint bytepos = i / 8;
      *IOSByteArray_GetRef(result, bytepos) = (jbyte) ((JreLShift32(IOSByteArray_Get(result, bytepos), 1)) | (last & 1));
    }
  }
  JreAssignVolatileBoolean(&stop_, true);
  return result;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoPrngThreadedSeedGenerator:);
  methods[1].selector = @selector(run);
  methods[2].selector = @selector(generateSeedWithInt:withBoolean:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "counter_", "I", .constantValue.asLong = 0, 0x42, -1, -1, -1, -1 },
    { "stop_", "Z", .constantValue.asLong = 0, 0x42, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "generateSeed", "IZ", "LLibOrgBouncycastleCryptoPrngThreadedSeedGenerator;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator = { "SeedGenerator", "lib.org.bouncycastle.crypto.prng", ptrTable, methods, fields, 7, 0x2, 3, 2, 2, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator;
}

@end

void LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator_initWithLibOrgBouncycastleCryptoPrngThreadedSeedGenerator_(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator *self, LibOrgBouncycastleCryptoPrngThreadedSeedGenerator *outer$) {
  NSObject_init(self);
  JreAssignVolatileInt(&self->counter_, 0);
  JreAssignVolatileBoolean(&self->stop_, false);
}

LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator *new_LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator_initWithLibOrgBouncycastleCryptoPrngThreadedSeedGenerator_(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator *outer$) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator, initWithLibOrgBouncycastleCryptoPrngThreadedSeedGenerator_, outer$)
}

LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator *create_LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator_initWithLibOrgBouncycastleCryptoPrngThreadedSeedGenerator_(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator *outer$) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator, initWithLibOrgBouncycastleCryptoPrngThreadedSeedGenerator_, outer$)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoPrngThreadedSeedGenerator_SeedGenerator)