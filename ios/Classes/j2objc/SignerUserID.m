//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/sig/SignerUserID.java
//

#include "Arrays.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "SignatureSubpacket.h"
#include "SignatureSubpacketTags.h"
#include "SignerUserID.h"
#include "Strings.h"

@implementation LibOrgBouncycastleBcpgSigSignerUserID

- (instancetype)initWithBoolean:(jboolean)critical
                    withBoolean:(jboolean)isLongLength
                  withByteArray:(IOSByteArray *)data {
  LibOrgBouncycastleBcpgSigSignerUserID_initWithBoolean_withBoolean_withByteArray_(self, critical, isLongLength, data);
  return self;
}

- (instancetype)initWithBoolean:(jboolean)critical
                   withNSString:(NSString *)userID {
  LibOrgBouncycastleBcpgSigSignerUserID_initWithBoolean_withNSString_(self, critical, userID);
  return self;
}

- (NSString *)getID {
  return LibOrgBouncycastleUtilStrings_fromUTF8ByteArrayWithByteArray_(data_);
}

- (IOSByteArray *)getRawID {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(data_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithBoolean:withBoolean:withByteArray:);
  methods[1].selector = @selector(initWithBoolean:withNSString:);
  methods[2].selector = @selector(getID);
  methods[3].selector = @selector(getRawID);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "ZZ[B", "ZLNSString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgSigSignerUserID = { "SignerUserID", "lib.org.bouncycastle.bcpg.sig", ptrTable, methods, NULL, 7, 0x1, 4, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgSigSignerUserID;
}

@end

void LibOrgBouncycastleBcpgSigSignerUserID_initWithBoolean_withBoolean_withByteArray_(LibOrgBouncycastleBcpgSigSignerUserID *self, jboolean critical, jboolean isLongLength, IOSByteArray *data) {
  LibOrgBouncycastleBcpgSignatureSubpacket_initWithInt_withBoolean_withBoolean_withByteArray_(self, LibOrgBouncycastleBcpgSignatureSubpacketTags_SIGNER_USER_ID, critical, isLongLength, data);
}

LibOrgBouncycastleBcpgSigSignerUserID *new_LibOrgBouncycastleBcpgSigSignerUserID_initWithBoolean_withBoolean_withByteArray_(jboolean critical, jboolean isLongLength, IOSByteArray *data) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgSigSignerUserID, initWithBoolean_withBoolean_withByteArray_, critical, isLongLength, data)
}

LibOrgBouncycastleBcpgSigSignerUserID *create_LibOrgBouncycastleBcpgSigSignerUserID_initWithBoolean_withBoolean_withByteArray_(jboolean critical, jboolean isLongLength, IOSByteArray *data) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgSigSignerUserID, initWithBoolean_withBoolean_withByteArray_, critical, isLongLength, data)
}

void LibOrgBouncycastleBcpgSigSignerUserID_initWithBoolean_withNSString_(LibOrgBouncycastleBcpgSigSignerUserID *self, jboolean critical, NSString *userID) {
  LibOrgBouncycastleBcpgSignatureSubpacket_initWithInt_withBoolean_withBoolean_withByteArray_(self, LibOrgBouncycastleBcpgSignatureSubpacketTags_SIGNER_USER_ID, critical, false, LibOrgBouncycastleUtilStrings_toUTF8ByteArrayWithNSString_(userID));
}

LibOrgBouncycastleBcpgSigSignerUserID *new_LibOrgBouncycastleBcpgSigSignerUserID_initWithBoolean_withNSString_(jboolean critical, NSString *userID) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgSigSignerUserID, initWithBoolean_withNSString_, critical, userID)
}

LibOrgBouncycastleBcpgSigSignerUserID *create_LibOrgBouncycastleBcpgSigSignerUserID_initWithBoolean_withNSString_(jboolean critical, NSString *userID) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgSigSignerUserID, initWithBoolean_withNSString_, critical, userID)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgSigSignerUserID)