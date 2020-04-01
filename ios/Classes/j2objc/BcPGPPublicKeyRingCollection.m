//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/bc/BcPGPPublicKeyRingCollection.java
//

#include "BcKeyFingerprintCalculator.h"
#include "BcPGPPublicKeyRingCollection.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PGPPublicKeyRingCollection.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/InputStream.h"
#include "java/util/Collection.h"

@implementation LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection

- (instancetype)initWithByteArray:(IOSByteArray *)encoding {
  LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection_initWithByteArray_(self, encoding);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)inArg {
  LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection_initWithJavaIoInputStream_(self, inArg);
  return self;
}

- (instancetype)initWithJavaUtilCollection:(id<JavaUtilCollection>)collection {
  LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection_initWithJavaUtilCollection_(self, collection);
  return self;
}

- (NSUInteger)countByEnumeratingWithState:(NSFastEnumerationState *)state objects:(__unsafe_unretained id *)stackbuf count:(NSUInteger)len {
  return JreDefaultFastEnumeration(self, state, stackbuf);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(initWithJavaIoInputStream:);
  methods[2].selector = @selector(initWithJavaUtilCollection:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "[B", "LJavaIoIOException;LLibOrgBouncycastleOpenpgpPGPException;", "LJavaIoInputStream;", "LJavaUtilCollection;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection = { "BcPGPPublicKeyRingCollection", "lib.org.bouncycastle.openpgp.bc", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection;
}

@end

void LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection_initWithByteArray_(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection *self, IOSByteArray *encoding) {
  LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection_initWithJavaIoInputStream_(self, new_JavaIoByteArrayInputStream_initWithByteArray_(encoding));
}

LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection *new_LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection_initWithByteArray_(IOSByteArray *encoding) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection, initWithByteArray_, encoding)
}

LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection *create_LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection_initWithByteArray_(IOSByteArray *encoding) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection, initWithByteArray_, encoding)
}

void LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection_initWithJavaIoInputStream_(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection *self, JavaIoInputStream *inArg) {
  LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(self, inArg, new_LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator_init());
}

LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection *new_LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection_initWithJavaIoInputStream_(JavaIoInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection, initWithJavaIoInputStream_, inArg)
}

LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection *create_LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection_initWithJavaIoInputStream_(JavaIoInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection, initWithJavaIoInputStream_, inArg)
}

void LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection_initWithJavaUtilCollection_(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection *self, id<JavaUtilCollection> collection) {
  LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_initWithJavaUtilCollection_(self, collection);
}

LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection *new_LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection_initWithJavaUtilCollection_(id<JavaUtilCollection> collection) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection, initWithJavaUtilCollection_, collection)
}

LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection *create_LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection_initWithJavaUtilCollection_(id<JavaUtilCollection> collection) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection, initWithJavaUtilCollection_, collection)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRingCollection)