//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/jcajce/JcaKeyFingerprintCalculator.java
//

#include "BCPGKey.h"
#include "DefaultJcaJceHelper.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcaJceHelper.h"
#include "JcaKeyFingerprintCalculator.h"
#include "MPInteger.h"
#include "NamedJcaJceHelper.h"
#include "PGPException.h"
#include "ProviderJcaJceHelper.h"
#include "PublicKeyPacket.h"
#include "RSAPublicBCPGKey.h"
#include "java/io/IOException.h"
#include "java/math/BigInteger.h"
#include "java/security/MessageDigest.h"
#include "java/security/NoSuchAlgorithmException.h"
#include "java/security/NoSuchProviderException.h"
#include "java/security/Provider.h"

@interface LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator () {
 @public
  id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper_;
}

- (instancetype)initWithLibOrgBouncycastleJcajceUtilJcaJceHelper:(id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)helper;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator, helper_, id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator *self, id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper);

@implementation LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleJcajceUtilJcaJceHelper:(id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)helper {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(self, helper);
  return self;
}

- (LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator *)setProviderWithJavaSecurityProvider:(JavaSecurityProvider *)provider {
  return new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(new_LibOrgBouncycastleJcajceUtilProviderJcaJceHelper_initWithJavaSecurityProvider_(provider));
}

- (LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator *)setProviderWithNSString:(NSString *)providerName {
  return new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(new_LibOrgBouncycastleJcajceUtilNamedJcaJceHelper_initWithNSString_(providerName));
}

- (IOSByteArray *)calculateFingerprintWithLibOrgBouncycastleBcpgPublicKeyPacket:(LibOrgBouncycastleBcpgPublicKeyPacket *)publicPk {
  id<LibOrgBouncycastleBcpgBCPGKey> key = [((LibOrgBouncycastleBcpgPublicKeyPacket *) nil_chk(publicPk)) getKey];
  if ([publicPk getVersion] <= 3) {
    LibOrgBouncycastleBcpgRSAPublicBCPGKey *rK = (LibOrgBouncycastleBcpgRSAPublicBCPGKey *) cast_chk(key, [LibOrgBouncycastleBcpgRSAPublicBCPGKey class]);
    @try {
      JavaSecurityMessageDigest *digest = [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(helper_)) createDigestWithNSString:@"MD5"];
      IOSByteArray *bytes = [new_LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_([((LibOrgBouncycastleBcpgRSAPublicBCPGKey *) nil_chk(rK)) getModulus]) getEncoded];
      [((JavaSecurityMessageDigest *) nil_chk(digest)) updateWithByteArray:bytes withInt:2 withInt:((IOSByteArray *) nil_chk(bytes))->size_ - 2];
      bytes = [new_LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_([rK getPublicExponent]) getEncoded];
      [digest updateWithByteArray:bytes withInt:2 withInt:((IOSByteArray *) nil_chk(bytes))->size_ - 2];
      return [digest digest];
    }
    @catch (JavaSecurityNoSuchAlgorithmException *e) {
      @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(@"can't find MD5", e);
    }
    @catch (JavaSecurityNoSuchProviderException *e) {
      @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(@"can't find MD5", e);
    }
    @catch (JavaIoIOException *e) {
      @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(JreStrcat("$$", @"can't encode key components: ", [e getMessage]), e);
    }
  }
  else {
    @try {
      IOSByteArray *kBytes = [publicPk getEncodedContents];
      JavaSecurityMessageDigest *digest = [((id<LibOrgBouncycastleJcajceUtilJcaJceHelper>) nil_chk(helper_)) createDigestWithNSString:@"SHA1"];
      [((JavaSecurityMessageDigest *) nil_chk(digest)) updateWithByte:(jbyte) (jint) 0x99];
      [digest updateWithByte:(jbyte) (JreRShift32(((IOSByteArray *) nil_chk(kBytes))->size_, 8))];
      [digest updateWithByte:(jbyte) kBytes->size_];
      [digest updateWithByteArray:kBytes];
      return [digest digest];
    }
    @catch (JavaSecurityNoSuchAlgorithmException *e) {
      @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(@"can't find SHA1", e);
    }
    @catch (JavaSecurityNoSuchProviderException *e) {
      @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(@"can't find SHA1", e);
    }
    @catch (JavaIoIOException *e) {
      @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(JreStrcat("$$", @"can't encode key components: ", [e getMessage]), e);
    }
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator;", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator;", 0x1, 1, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 4, 5, 6, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithLibOrgBouncycastleJcajceUtilJcaJceHelper:);
  methods[2].selector = @selector(setProviderWithJavaSecurityProvider:);
  methods[3].selector = @selector(setProviderWithNSString:);
  methods[4].selector = @selector(calculateFingerprintWithLibOrgBouncycastleBcpgPublicKeyPacket:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "helper_", "LLibOrgBouncycastleJcajceUtilJcaJceHelper;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceUtilJcaJceHelper;", "setProvider", "LJavaSecurityProvider;", "LNSString;", "calculateFingerprint", "LLibOrgBouncycastleBcpgPublicKeyPacket;", "LLibOrgBouncycastleOpenpgpPGPException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator = { "JcaKeyFingerprintCalculator", "lib.org.bouncycastle.openpgp.operator.jcajce", ptrTable, methods, fields, 7, 0x1, 5, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator;
}

@end

void LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_init(LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator *self) {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(self, new_LibOrgBouncycastleJcajceUtilDefaultJcaJceHelper_init());
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator, init)
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator, init)
}

void LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator *self, id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper) {
  NSObject_init(self);
  self->helper_ = helper;
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator, initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_, helper)
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator, initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_, helper)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator)
