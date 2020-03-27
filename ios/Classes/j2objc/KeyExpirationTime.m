//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/sig/KeyExpirationTime.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyExpirationTime.h"
#include "SignatureSubpacket.h"
#include "SignatureSubpacketTags.h"

@implementation LibOrgBouncycastleBcpgSigKeyExpirationTime

+ (IOSByteArray *)timeToBytesWithLong:(jlong)t {
  return LibOrgBouncycastleBcpgSigKeyExpirationTime_timeToBytesWithLong_(t);
}

- (instancetype)initWithBoolean:(jboolean)critical
                    withBoolean:(jboolean)isLongLength
                  withByteArray:(IOSByteArray *)data {
  LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withBoolean_withByteArray_(self, critical, isLongLength, data);
  return self;
}

- (instancetype)initWithBoolean:(jboolean)critical
                       withLong:(jlong)seconds {
  LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withLong_(self, critical, seconds);
  return self;
}

- (jlong)getTime {
  jlong time = (JreLShift64((jlong) (IOSByteArray_Get(nil_chk(data_), 0) & (jint) 0xff), 24)) | (JreLShift32((IOSByteArray_Get(data_, 1) & (jint) 0xff), 16)) | (JreLShift32((IOSByteArray_Get(data_, 2) & (jint) 0xff), 8)) | (IOSByteArray_Get(data_, 3) & (jint) 0xff);
  return time;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "[B", 0xc, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(timeToBytesWithLong:);
  methods[1].selector = @selector(initWithBoolean:withBoolean:withByteArray:);
  methods[2].selector = @selector(initWithBoolean:withLong:);
  methods[3].selector = @selector(getTime);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "timeToBytes", "J", "ZZ[B", "ZJ" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgSigKeyExpirationTime = { "KeyExpirationTime", "lib.org.bouncycastle.bcpg.sig", ptrTable, methods, NULL, 7, 0x1, 4, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgSigKeyExpirationTime;
}

@end

IOSByteArray *LibOrgBouncycastleBcpgSigKeyExpirationTime_timeToBytesWithLong_(jlong t) {
  LibOrgBouncycastleBcpgSigKeyExpirationTime_initialize();
  IOSByteArray *data = [IOSByteArray newArrayWithLength:4];
  *IOSByteArray_GetRef(data, 0) = (jbyte) (JreRShift64(t, 24));
  *IOSByteArray_GetRef(data, 1) = (jbyte) (JreRShift64(t, 16));
  *IOSByteArray_GetRef(data, 2) = (jbyte) (JreRShift64(t, 8));
  *IOSByteArray_GetRef(data, 3) = (jbyte) t;
  return data;
}

void LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withBoolean_withByteArray_(LibOrgBouncycastleBcpgSigKeyExpirationTime *self, jboolean critical, jboolean isLongLength, IOSByteArray *data) {
  LibOrgBouncycastleBcpgSignatureSubpacket_initWithInt_withBoolean_withBoolean_withByteArray_(self, LibOrgBouncycastleBcpgSignatureSubpacketTags_KEY_EXPIRE_TIME, critical, isLongLength, data);
}

LibOrgBouncycastleBcpgSigKeyExpirationTime *new_LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withBoolean_withByteArray_(jboolean critical, jboolean isLongLength, IOSByteArray *data) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgSigKeyExpirationTime, initWithBoolean_withBoolean_withByteArray_, critical, isLongLength, data)
}

LibOrgBouncycastleBcpgSigKeyExpirationTime *create_LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withBoolean_withByteArray_(jboolean critical, jboolean isLongLength, IOSByteArray *data) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgSigKeyExpirationTime, initWithBoolean_withBoolean_withByteArray_, critical, isLongLength, data)
}

void LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withLong_(LibOrgBouncycastleBcpgSigKeyExpirationTime *self, jboolean critical, jlong seconds) {
  LibOrgBouncycastleBcpgSignatureSubpacket_initWithInt_withBoolean_withBoolean_withByteArray_(self, LibOrgBouncycastleBcpgSignatureSubpacketTags_KEY_EXPIRE_TIME, critical, false, LibOrgBouncycastleBcpgSigKeyExpirationTime_timeToBytesWithLong_(seconds));
}

LibOrgBouncycastleBcpgSigKeyExpirationTime *new_LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withLong_(jboolean critical, jlong seconds) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgSigKeyExpirationTime, initWithBoolean_withLong_, critical, seconds)
}

LibOrgBouncycastleBcpgSigKeyExpirationTime *create_LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withLong_(jboolean critical, jlong seconds) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgSigKeyExpirationTime, initWithBoolean_withLong_, critical, seconds)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgSigKeyExpirationTime)