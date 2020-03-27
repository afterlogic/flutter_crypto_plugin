//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/SRTPProtectionProfile.java
//

#include "J2ObjC_source.h"
#include "SRTPProtectionProfile.h"

@implementation LibOrgBouncycastleCryptoTlsSRTPProtectionProfile

+ (jint)SRTP_AES128_CM_HMAC_SHA1_80 {
  return LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_SRTP_AES128_CM_HMAC_SHA1_80;
}

+ (jint)SRTP_AES128_CM_HMAC_SHA1_32 {
  return LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_SRTP_AES128_CM_HMAC_SHA1_32;
}

+ (jint)SRTP_NULL_HMAC_SHA1_80 {
  return LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_SRTP_NULL_HMAC_SHA1_80;
}

+ (jint)SRTP_NULL_HMAC_SHA1_32 {
  return LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_SRTP_NULL_HMAC_SHA1_32;
}

+ (jint)SRTP_AEAD_AES_128_GCM {
  return LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_SRTP_AEAD_AES_128_GCM;
}

+ (jint)SRTP_AEAD_AES_256_GCM {
  return LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_SRTP_AEAD_AES_256_GCM;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_init(self);
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
  static const J2ObjcFieldInfo fields[] = {
    { "SRTP_AES128_CM_HMAC_SHA1_80", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_SRTP_AES128_CM_HMAC_SHA1_80, 0x19, -1, -1, -1, -1 },
    { "SRTP_AES128_CM_HMAC_SHA1_32", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_SRTP_AES128_CM_HMAC_SHA1_32, 0x19, -1, -1, -1, -1 },
    { "SRTP_NULL_HMAC_SHA1_80", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_SRTP_NULL_HMAC_SHA1_80, 0x19, -1, -1, -1, -1 },
    { "SRTP_NULL_HMAC_SHA1_32", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_SRTP_NULL_HMAC_SHA1_32, 0x19, -1, -1, -1, -1 },
    { "SRTP_AEAD_AES_128_GCM", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_SRTP_AEAD_AES_128_GCM, 0x19, -1, -1, -1, -1 },
    { "SRTP_AEAD_AES_256_GCM", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_SRTP_AEAD_AES_256_GCM, 0x19, -1, -1, -1, -1 },
  };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsSRTPProtectionProfile = { "SRTPProtectionProfile", "lib.org.bouncycastle.crypto.tls", NULL, methods, fields, 7, 0x1, 1, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsSRTPProtectionProfile;
}

@end

void LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_init(LibOrgBouncycastleCryptoTlsSRTPProtectionProfile *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoTlsSRTPProtectionProfile *new_LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsSRTPProtectionProfile, init)
}

LibOrgBouncycastleCryptoTlsSRTPProtectionProfile *create_LibOrgBouncycastleCryptoTlsSRTPProtectionProfile_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsSRTPProtectionProfile, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsSRTPProtectionProfile)
