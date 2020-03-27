//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/DefaultTlsCipherFactory.java
//

#include "AEADBlockCipher.h"
#include "AESEngine.h"
#include "AbstractTlsCipherFactory.h"
#include "AlertDescription.h"
#include "BlockCipher.h"
#include "CBCBlockCipher.h"
#include "CCMBlockCipher.h"
#include "CamelliaEngine.h"
#include "Chacha20Poly1305.h"
#include "DESedeEngine.h"
#include "DefaultTlsCipherFactory.h"
#include "Digest.h"
#include "EncryptionAlgorithm.h"
#include "GCMBlockCipher.h"
#include "HashAlgorithm.h"
#include "J2ObjC_source.h"
#include "MACAlgorithm.h"
#include "OCBBlockCipher.h"
#include "RC4Engine.h"
#include "SEEDEngine.h"
#include "StreamCipher.h"
#include "TlsAEADCipher.h"
#include "TlsBlockCipher.h"
#include "TlsCipher.h"
#include "TlsContext.h"
#include "TlsFatalAlert.h"
#include "TlsNullCipher.h"
#include "TlsStreamCipher.h"
#include "TlsUtils.h"

@implementation LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id<LibOrgBouncycastleCryptoTlsTlsCipher>)createCipherWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                                                          withInt:(jint)encryptionAlgorithm
                                                                                          withInt:(jint)macAlgorithm {
  switch (encryptionAlgorithm) {
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm__3DES_EDE_CBC:
    return [self createDESedeCipherWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:macAlgorithm];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_AES_128_CBC:
    return [self createAESCipherWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:16 withInt:macAlgorithm];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_AES_128_CCM:
    return [self createCipher_AES_CCMWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:16 withInt:16];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_AES_128_CCM_8:
    return [self createCipher_AES_CCMWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:16 withInt:8];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_AES_128_GCM:
    return [self createCipher_AES_GCMWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:16 withInt:16];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_AES_128_OCB_TAGLEN96:
    return [self createCipher_AES_OCBWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:16 withInt:12];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_AES_256_CBC:
    return [self createAESCipherWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:32 withInt:macAlgorithm];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_AES_256_CCM:
    return [self createCipher_AES_CCMWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:32 withInt:16];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_AES_256_CCM_8:
    return [self createCipher_AES_CCMWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:32 withInt:8];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_AES_256_GCM:
    return [self createCipher_AES_GCMWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:32 withInt:16];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_AES_256_OCB_TAGLEN96:
    return [self createCipher_AES_OCBWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:32 withInt:12];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_CAMELLIA_128_CBC:
    return [self createCamelliaCipherWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:16 withInt:macAlgorithm];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_CAMELLIA_128_GCM:
    return [self createCipher_Camellia_GCMWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:16 withInt:16];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_CAMELLIA_256_CBC:
    return [self createCamelliaCipherWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:32 withInt:macAlgorithm];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_CAMELLIA_256_GCM:
    return [self createCipher_Camellia_GCMWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:32 withInt:16];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_CHACHA20_POLY1305:
    return [self createChaCha20Poly1305WithLibOrgBouncycastleCryptoTlsTlsContext:context];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_NULL:
    return [self createNullCipherWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:macAlgorithm];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_RC4_128:
    return [self createRC4CipherWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:16 withInt:macAlgorithm];
    case LibOrgBouncycastleCryptoTlsEncryptionAlgorithm_SEED_CBC:
    return [self createSEEDCipherWithLibOrgBouncycastleCryptoTlsTlsContext:context withInt:macAlgorithm];
    default:
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
}

- (LibOrgBouncycastleCryptoTlsTlsBlockCipher *)createAESCipherWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                                                                withInt:(jint)cipherKeySize
                                                                                                withInt:(jint)macAlgorithm {
  return new_LibOrgBouncycastleCryptoTlsTlsBlockCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_withInt_(context, [self createAESBlockCipher], [self createAESBlockCipher], [self createHMACDigestWithInt:macAlgorithm], [self createHMACDigestWithInt:macAlgorithm], cipherKeySize);
}

- (LibOrgBouncycastleCryptoTlsTlsBlockCipher *)createCamelliaCipherWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                                                                     withInt:(jint)cipherKeySize
                                                                                                     withInt:(jint)macAlgorithm {
  return new_LibOrgBouncycastleCryptoTlsTlsBlockCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_withInt_(context, [self createCamelliaBlockCipher], [self createCamelliaBlockCipher], [self createHMACDigestWithInt:macAlgorithm], [self createHMACDigestWithInt:macAlgorithm], cipherKeySize);
}

- (id<LibOrgBouncycastleCryptoTlsTlsCipher>)createChaCha20Poly1305WithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context {
  return new_LibOrgBouncycastleCryptoTlsChacha20Poly1305_initWithLibOrgBouncycastleCryptoTlsTlsContext_(context);
}

- (LibOrgBouncycastleCryptoTlsTlsAEADCipher *)createCipher_AES_CCMWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                                                                    withInt:(jint)cipherKeySize
                                                                                                    withInt:(jint)macSize {
  return new_LibOrgBouncycastleCryptoTlsTlsAEADCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withInt_withInt_(context, [self createAEADBlockCipher_AES_CCM], [self createAEADBlockCipher_AES_CCM], cipherKeySize, macSize);
}

- (LibOrgBouncycastleCryptoTlsTlsAEADCipher *)createCipher_AES_GCMWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                                                                    withInt:(jint)cipherKeySize
                                                                                                    withInt:(jint)macSize {
  return new_LibOrgBouncycastleCryptoTlsTlsAEADCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withInt_withInt_(context, [self createAEADBlockCipher_AES_GCM], [self createAEADBlockCipher_AES_GCM], cipherKeySize, macSize);
}

- (LibOrgBouncycastleCryptoTlsTlsAEADCipher *)createCipher_AES_OCBWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                                                                    withInt:(jint)cipherKeySize
                                                                                                    withInt:(jint)macSize {
  return new_LibOrgBouncycastleCryptoTlsTlsAEADCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withInt_withInt_withInt_(context, [self createAEADBlockCipher_AES_OCB], [self createAEADBlockCipher_AES_OCB], cipherKeySize, macSize, LibOrgBouncycastleCryptoTlsTlsAEADCipher_NONCE_DRAFT_CHACHA20_POLY1305);
}

- (LibOrgBouncycastleCryptoTlsTlsAEADCipher *)createCipher_Camellia_GCMWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                                                                         withInt:(jint)cipherKeySize
                                                                                                         withInt:(jint)macSize {
  return new_LibOrgBouncycastleCryptoTlsTlsAEADCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withLibOrgBouncycastleCryptoModesAEADBlockCipher_withInt_withInt_(context, [self createAEADBlockCipher_Camellia_GCM], [self createAEADBlockCipher_Camellia_GCM], cipherKeySize, macSize);
}

- (LibOrgBouncycastleCryptoTlsTlsBlockCipher *)createDESedeCipherWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                                                                   withInt:(jint)macAlgorithm {
  return new_LibOrgBouncycastleCryptoTlsTlsBlockCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_withInt_(context, [self createDESedeBlockCipher], [self createDESedeBlockCipher], [self createHMACDigestWithInt:macAlgorithm], [self createHMACDigestWithInt:macAlgorithm], 24);
}

- (LibOrgBouncycastleCryptoTlsTlsNullCipher *)createNullCipherWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                                                                withInt:(jint)macAlgorithm {
  return new_LibOrgBouncycastleCryptoTlsTlsNullCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_(context, [self createHMACDigestWithInt:macAlgorithm], [self createHMACDigestWithInt:macAlgorithm]);
}

- (LibOrgBouncycastleCryptoTlsTlsStreamCipher *)createRC4CipherWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                                                                 withInt:(jint)cipherKeySize
                                                                                                 withInt:(jint)macAlgorithm {
  return new_LibOrgBouncycastleCryptoTlsTlsStreamCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoStreamCipher_withLibOrgBouncycastleCryptoStreamCipher_withLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_withInt_withBoolean_(context, [self createRC4StreamCipher], [self createRC4StreamCipher], [self createHMACDigestWithInt:macAlgorithm], [self createHMACDigestWithInt:macAlgorithm], cipherKeySize, false);
}

- (LibOrgBouncycastleCryptoTlsTlsBlockCipher *)createSEEDCipherWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                                                                 withInt:(jint)macAlgorithm {
  return new_LibOrgBouncycastleCryptoTlsTlsBlockCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_withInt_(context, [self createSEEDBlockCipher], [self createSEEDBlockCipher], [self createHMACDigestWithInt:macAlgorithm], [self createHMACDigestWithInt:macAlgorithm], 16);
}

- (id<LibOrgBouncycastleCryptoBlockCipher>)createAESEngine {
  return new_LibOrgBouncycastleCryptoEnginesAESEngine_init();
}

- (id<LibOrgBouncycastleCryptoBlockCipher>)createCamelliaEngine {
  return new_LibOrgBouncycastleCryptoEnginesCamelliaEngine_init();
}

- (id<LibOrgBouncycastleCryptoBlockCipher>)createAESBlockCipher {
  return new_LibOrgBouncycastleCryptoModesCBCBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_([self createAESEngine]);
}

- (id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)createAEADBlockCipher_AES_CCM {
  return new_LibOrgBouncycastleCryptoModesCCMBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_([self createAESEngine]);
}

- (id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)createAEADBlockCipher_AES_GCM {
  return new_LibOrgBouncycastleCryptoModesGCMBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_([self createAESEngine]);
}

- (id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)createAEADBlockCipher_AES_OCB {
  return new_LibOrgBouncycastleCryptoModesOCBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_([self createAESEngine], [self createAESEngine]);
}

- (id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)createAEADBlockCipher_Camellia_GCM {
  return new_LibOrgBouncycastleCryptoModesGCMBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_([self createCamelliaEngine]);
}

- (id<LibOrgBouncycastleCryptoBlockCipher>)createCamelliaBlockCipher {
  return new_LibOrgBouncycastleCryptoModesCBCBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_([self createCamelliaEngine]);
}

- (id<LibOrgBouncycastleCryptoBlockCipher>)createDESedeBlockCipher {
  return new_LibOrgBouncycastleCryptoModesCBCBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(new_LibOrgBouncycastleCryptoEnginesDESedeEngine_init());
}

- (id<LibOrgBouncycastleCryptoStreamCipher>)createRC4StreamCipher {
  return new_LibOrgBouncycastleCryptoEnginesRC4Engine_init();
}

- (id<LibOrgBouncycastleCryptoBlockCipher>)createSEEDBlockCipher {
  return new_LibOrgBouncycastleCryptoModesCBCBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(new_LibOrgBouncycastleCryptoEnginesSEEDEngine_init());
}

- (id<LibOrgBouncycastleCryptoDigest>)createHMACDigestWithInt:(jint)macAlgorithm {
  switch (macAlgorithm) {
    case LibOrgBouncycastleCryptoTlsMACAlgorithm__null:
    return nil;
    case LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_md5:
    return LibOrgBouncycastleCryptoTlsTlsUtils_createHashWithShort_(LibOrgBouncycastleCryptoTlsHashAlgorithm_md5);
    case LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_sha1:
    return LibOrgBouncycastleCryptoTlsTlsUtils_createHashWithShort_(LibOrgBouncycastleCryptoTlsHashAlgorithm_sha1);
    case LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_sha256:
    return LibOrgBouncycastleCryptoTlsTlsUtils_createHashWithShort_(LibOrgBouncycastleCryptoTlsHashAlgorithm_sha256);
    case LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_sha384:
    return LibOrgBouncycastleCryptoTlsTlsUtils_createHashWithShort_(LibOrgBouncycastleCryptoTlsHashAlgorithm_sha384);
    case LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_sha512:
    return LibOrgBouncycastleCryptoTlsTlsUtils_createHashWithShort_(LibOrgBouncycastleCryptoTlsHashAlgorithm_sha512);
    default:
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsCipher;", 0x1, 0, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsBlockCipher;", 0x4, 3, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsBlockCipher;", 0x4, 4, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsCipher;", 0x4, 5, 6, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsAEADCipher;", 0x4, 7, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsAEADCipher;", 0x4, 8, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsAEADCipher;", 0x4, 9, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsAEADCipher;", 0x4, 10, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsBlockCipher;", 0x4, 11, 12, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsNullCipher;", 0x4, 13, 12, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsStreamCipher;", 0x4, 14, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsBlockCipher;", 0x4, 15, 12, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoBlockCipher;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoBlockCipher;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoBlockCipher;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoModesAEADBlockCipher;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoModesAEADBlockCipher;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoModesAEADBlockCipher;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoModesAEADBlockCipher;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoBlockCipher;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoBlockCipher;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoStreamCipher;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoBlockCipher;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoDigest;", 0x4, 16, 17, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(createCipherWithLibOrgBouncycastleCryptoTlsTlsContext:withInt:withInt:);
  methods[2].selector = @selector(createAESCipherWithLibOrgBouncycastleCryptoTlsTlsContext:withInt:withInt:);
  methods[3].selector = @selector(createCamelliaCipherWithLibOrgBouncycastleCryptoTlsTlsContext:withInt:withInt:);
  methods[4].selector = @selector(createChaCha20Poly1305WithLibOrgBouncycastleCryptoTlsTlsContext:);
  methods[5].selector = @selector(createCipher_AES_CCMWithLibOrgBouncycastleCryptoTlsTlsContext:withInt:withInt:);
  methods[6].selector = @selector(createCipher_AES_GCMWithLibOrgBouncycastleCryptoTlsTlsContext:withInt:withInt:);
  methods[7].selector = @selector(createCipher_AES_OCBWithLibOrgBouncycastleCryptoTlsTlsContext:withInt:withInt:);
  methods[8].selector = @selector(createCipher_Camellia_GCMWithLibOrgBouncycastleCryptoTlsTlsContext:withInt:withInt:);
  methods[9].selector = @selector(createDESedeCipherWithLibOrgBouncycastleCryptoTlsTlsContext:withInt:);
  methods[10].selector = @selector(createNullCipherWithLibOrgBouncycastleCryptoTlsTlsContext:withInt:);
  methods[11].selector = @selector(createRC4CipherWithLibOrgBouncycastleCryptoTlsTlsContext:withInt:withInt:);
  methods[12].selector = @selector(createSEEDCipherWithLibOrgBouncycastleCryptoTlsTlsContext:withInt:);
  methods[13].selector = @selector(createAESEngine);
  methods[14].selector = @selector(createCamelliaEngine);
  methods[15].selector = @selector(createAESBlockCipher);
  methods[16].selector = @selector(createAEADBlockCipher_AES_CCM);
  methods[17].selector = @selector(createAEADBlockCipher_AES_GCM);
  methods[18].selector = @selector(createAEADBlockCipher_AES_OCB);
  methods[19].selector = @selector(createAEADBlockCipher_Camellia_GCM);
  methods[20].selector = @selector(createCamelliaBlockCipher);
  methods[21].selector = @selector(createDESedeBlockCipher);
  methods[22].selector = @selector(createRC4StreamCipher);
  methods[23].selector = @selector(createSEEDBlockCipher);
  methods[24].selector = @selector(createHMACDigestWithInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "createCipher", "LLibOrgBouncycastleCryptoTlsTlsContext;II", "LJavaIoIOException;", "createAESCipher", "createCamelliaCipher", "createChaCha20Poly1305", "LLibOrgBouncycastleCryptoTlsTlsContext;", "createCipher_AES_CCM", "createCipher_AES_GCM", "createCipher_AES_OCB", "createCipher_Camellia_GCM", "createDESedeCipher", "LLibOrgBouncycastleCryptoTlsTlsContext;I", "createNullCipher", "createRC4Cipher", "createSEEDCipher", "createHMACDigest", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory = { "DefaultTlsCipherFactory", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, NULL, 7, 0x1, 25, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory;
}

@end

void LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory_init(LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory *self) {
  LibOrgBouncycastleCryptoTlsAbstractTlsCipherFactory_init(self);
}

LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory *new_LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory, init)
}

LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory *create_LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory)
