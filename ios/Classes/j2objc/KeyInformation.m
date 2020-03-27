//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/gpg/keybox/KeyInformation.java
//

#include "Arrays.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyBoxByteBuffer.h"
#include "KeyInformation.h"

@interface LibOrgBouncycastleGpgKeyboxKeyInformation () {
 @public
  IOSByteArray *fingerprint_;
  jlong offsetToKeyID_;
  jint keyFlags_;
  IOSByteArray *filler_;
  IOSByteArray *keyID_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleGpgKeyboxKeyInformation, fingerprint_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleGpgKeyboxKeyInformation, filler_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleGpgKeyboxKeyInformation, keyID_, IOSByteArray *)

@implementation LibOrgBouncycastleGpgKeyboxKeyInformation

- (instancetype)initWithByteArray:(IOSByteArray *)fingerprint
                         withLong:(jlong)offsetToKeyID
                          withInt:(jint)keyFlags
                    withByteArray:(IOSByteArray *)filler
                    withByteArray:(IOSByteArray *)keyID {
  LibOrgBouncycastleGpgKeyboxKeyInformation_initWithByteArray_withLong_withInt_withByteArray_withByteArray_(self, fingerprint, offsetToKeyID, keyFlags, filler, keyID);
  return self;
}

+ (LibOrgBouncycastleGpgKeyboxKeyInformation *)getInstanceWithId:(id)src
                                                         withInt:(jint)expectedSize
                                                         withInt:(jint)base {
  return LibOrgBouncycastleGpgKeyboxKeyInformation_getInstanceWithId_withInt_withInt_(src, expectedSize, base);
}

- (IOSByteArray *)getFingerprint {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(fingerprint_);
}

- (jint)getKeyFlags {
  return keyFlags_;
}

- (IOSByteArray *)getFiller {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(filler_);
}

- (IOSByteArray *)getKeyID {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(keyID_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleGpgKeyboxKeyInformation;", 0x8, 1, 2, 3, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:withLong:withInt:withByteArray:withByteArray:);
  methods[1].selector = @selector(getInstanceWithId:withInt:withInt:);
  methods[2].selector = @selector(getFingerprint);
  methods[3].selector = @selector(getKeyFlags);
  methods[4].selector = @selector(getFiller);
  methods[5].selector = @selector(getKeyID);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "fingerprint_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "offsetToKeyID_", "J", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "keyFlags_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "filler_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "keyID_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[BJI[B[B", "getInstance", "LNSObject;II", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleGpgKeyboxKeyInformation = { "KeyInformation", "lib.org.bouncycastle.gpg.keybox", ptrTable, methods, fields, 7, 0x1, 6, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleGpgKeyboxKeyInformation;
}

@end

void LibOrgBouncycastleGpgKeyboxKeyInformation_initWithByteArray_withLong_withInt_withByteArray_withByteArray_(LibOrgBouncycastleGpgKeyboxKeyInformation *self, IOSByteArray *fingerprint, jlong offsetToKeyID, jint keyFlags, IOSByteArray *filler, IOSByteArray *keyID) {
  NSObject_init(self);
  self->fingerprint_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(fingerprint);
  self->offsetToKeyID_ = offsetToKeyID;
  self->keyFlags_ = keyFlags;
  self->filler_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(filler);
  self->keyID_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(keyID);
}

LibOrgBouncycastleGpgKeyboxKeyInformation *new_LibOrgBouncycastleGpgKeyboxKeyInformation_initWithByteArray_withLong_withInt_withByteArray_withByteArray_(IOSByteArray *fingerprint, jlong offsetToKeyID, jint keyFlags, IOSByteArray *filler, IOSByteArray *keyID) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleGpgKeyboxKeyInformation, initWithByteArray_withLong_withInt_withByteArray_withByteArray_, fingerprint, offsetToKeyID, keyFlags, filler, keyID)
}

LibOrgBouncycastleGpgKeyboxKeyInformation *create_LibOrgBouncycastleGpgKeyboxKeyInformation_initWithByteArray_withLong_withInt_withByteArray_withByteArray_(IOSByteArray *fingerprint, jlong offsetToKeyID, jint keyFlags, IOSByteArray *filler, IOSByteArray *keyID) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleGpgKeyboxKeyInformation, initWithByteArray_withLong_withInt_withByteArray_withByteArray_, fingerprint, offsetToKeyID, keyFlags, filler, keyID)
}

LibOrgBouncycastleGpgKeyboxKeyInformation *LibOrgBouncycastleGpgKeyboxKeyInformation_getInstanceWithId_withInt_withInt_(id src, jint expectedSize, jint base) {
  LibOrgBouncycastleGpgKeyboxKeyInformation_initialize();
  if ([src isKindOfClass:[LibOrgBouncycastleGpgKeyboxKeyInformation class]]) {
    return (LibOrgBouncycastleGpgKeyboxKeyInformation *) src;
  }
  LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *buffer = LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_wrapWithId_(src);
  jint start = [((LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *) nil_chk(buffer)) position];
  IOSByteArray *fingerPrint = [IOSByteArray newArrayWithLength:20];
  [buffer bNWithByteArray:fingerPrint];
  jlong offsetToKeyID = [buffer u32];
  IOSByteArray *keyID = nil;
  if (offsetToKeyID > 0) {
    keyID = [buffer rangeOfWithInt:(jint) (base + offsetToKeyID) withInt:(jint) (base + offsetToKeyID + 8)];
  }
  jint keyFlags = [buffer u16];
  [buffer u16];
  IOSByteArray *filler = [IOSByteArray newArrayWithLength:expectedSize - ([buffer position] - start)];
  [buffer bNWithByteArray:filler];
  return new_LibOrgBouncycastleGpgKeyboxKeyInformation_initWithByteArray_withLong_withInt_withByteArray_withByteArray_(fingerPrint, offsetToKeyID, keyFlags, filler, keyID);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleGpgKeyboxKeyInformation)
