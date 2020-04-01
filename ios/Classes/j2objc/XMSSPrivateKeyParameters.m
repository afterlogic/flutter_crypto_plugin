//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/XMSSPrivateKeyParameters.java
//

#include "ASN1ObjectIdentifier.h"
#include "Arrays.h"
#include "BDS.h"
#include "Digest.h"
#include "DigestUtil.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "OTSHashAddress.h"
#include "Pack.h"
#include "XMSSAddress.h"
#include "XMSSKeyParameters.h"
#include "XMSSParameters.h"
#include "XMSSPrivateKeyParameters.h"
#include "XMSSUtil.h"
#include "java/io/IOException.h"
#include "java/lang/ClassNotFoundException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/NullPointerException.h"
#include "java/lang/RuntimeException.h"

@interface LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters () {
 @public
  LibOrgBouncycastlePqcCryptoXmssXMSSParameters *params_;
  IOSByteArray *secretKeySeed_;
  IOSByteArray *secretKeyPRF_;
  IOSByteArray *publicSeed_;
  IOSByteArray *root_;
  LibOrgBouncycastlePqcCryptoXmssBDS *bdsState_;
}

- (instancetype)initWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder:(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *)builder;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters, params_, LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters, secretKeySeed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters, secretKeyPRF_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters, publicSeed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters, root_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters, bdsState_, LibOrgBouncycastlePqcCryptoXmssBDS *)

__attribute__((unused)) static void LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *self, LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *builder);

__attribute__((unused)) static LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *builder) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *builder);

@interface LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder () {
 @public
  LibOrgBouncycastlePqcCryptoXmssXMSSParameters *params_;
  jint index_;
  IOSByteArray *secretKeySeed_;
  IOSByteArray *secretKeyPRF_;
  IOSByteArray *publicSeed_;
  IOSByteArray *root_;
  LibOrgBouncycastlePqcCryptoXmssBDS *bdsState_;
  IOSByteArray *privateKey_;
  LibOrgBouncycastlePqcCryptoXmssXMSSParameters *xmss_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder, params_, LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder, secretKeySeed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder, secretKeyPRF_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder, publicSeed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder, root_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder, bdsState_, LibOrgBouncycastlePqcCryptoXmssBDS *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder, privateKey_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder, xmss_, LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)

@implementation LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters

- (instancetype)initWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder:(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *)builder {
  LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_(self, builder);
  return self;
}

- (jlong)getUsagesRemaining {
  return (JreLShift64(1LL, [((LibOrgBouncycastlePqcCryptoXmssXMSSParameters *) nil_chk([self getParameters])) getHeight])) - [self getIndex];
}

- (IOSByteArray *)toByteArray {
  jint n = [((LibOrgBouncycastlePqcCryptoXmssXMSSParameters *) nil_chk(params_)) getDigestSize];
  jint indexSize = 4;
  jint secretKeySize = n;
  jint secretKeyPRFSize = n;
  jint publicSeedSize = n;
  jint rootSize = n;
  jint totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
  IOSByteArray *out = [IOSByteArray newArrayWithLength:totalSize];
  jint position = 0;
  LibOrgBouncycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_([((LibOrgBouncycastlePqcCryptoXmssBDS *) nil_chk(bdsState_)) getIndex], out, position);
  position += indexSize;
  LibOrgBouncycastlePqcCryptoXmssXMSSUtil_copyBytesAtOffsetWithByteArray_withByteArray_withInt_(out, secretKeySeed_, position);
  position += secretKeySize;
  LibOrgBouncycastlePqcCryptoXmssXMSSUtil_copyBytesAtOffsetWithByteArray_withByteArray_withInt_(out, secretKeyPRF_, position);
  position += secretKeyPRFSize;
  LibOrgBouncycastlePqcCryptoXmssXMSSUtil_copyBytesAtOffsetWithByteArray_withByteArray_withInt_(out, publicSeed_, position);
  position += publicSeedSize;
  LibOrgBouncycastlePqcCryptoXmssXMSSUtil_copyBytesAtOffsetWithByteArray_withByteArray_withInt_(out, root_, position);
  IOSByteArray *bdsStateOut = nil;
  @try {
    bdsStateOut = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_serializeWithId_(bdsState_);
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangRuntimeException_initWithNSString_(JreStrcat("$$", @"error serializing bds state: ", [e getMessage]));
  }
  return LibOrgBouncycastleUtilArrays_concatenateWithByteArray_withByteArray_(out, bdsStateOut);
}

- (jint)getIndex {
  return [((LibOrgBouncycastlePqcCryptoXmssBDS *) nil_chk(bdsState_)) getIndex];
}

- (IOSByteArray *)getSecretKeySeed {
  return LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(secretKeySeed_);
}

- (IOSByteArray *)getSecretKeyPRF {
  return LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(secretKeyPRF_);
}

- (IOSByteArray *)getPublicSeed {
  return LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(publicSeed_);
}

- (IOSByteArray *)getRoot {
  return LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(root_);
}

- (LibOrgBouncycastlePqcCryptoXmssBDS *)getBDSState {
  return bdsState_;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)getParameters {
  return params_;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *)getNextKey {
  jint treeHeight = [((LibOrgBouncycastlePqcCryptoXmssXMSSParameters *) nil_chk(self->params_)) getHeight];
  if ([self getIndex] < ((JreLShift32(1, treeHeight)) - 1)) {
    return [((LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *) nil_chk([new_LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_(params_) withSecretKeySeedWithByteArray:secretKeySeed_])) withSecretKeyPRFWithByteArray:secretKeyPRF_])) withPublicSeedWithByteArray:publicSeed_])) withRootWithByteArray:root_])) withBDSStateWithLibOrgBouncycastlePqcCryptoXmssBDS:[((LibOrgBouncycastlePqcCryptoXmssBDS *) nil_chk(bdsState_)) getNextStateWithByteArray:publicSeed_ withByteArray:secretKeySeed_ withLibOrgBouncycastlePqcCryptoXmssOTSHashAddress:(LibOrgBouncycastlePqcCryptoXmssOTSHashAddress *) cast_chk([new_LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder_init() build], [LibOrgBouncycastlePqcCryptoXmssOTSHashAddress class])]])) build];
  }
  else {
    return [((LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *) nil_chk([new_LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_(params_) withSecretKeySeedWithByteArray:secretKeySeed_])) withSecretKeyPRFWithByteArray:secretKeyPRF_])) withPublicSeedWithByteArray:publicSeed_])) withRootWithByteArray:root_])) withBDSStateWithLibOrgBouncycastlePqcCryptoXmssBDS:new_LibOrgBouncycastlePqcCryptoXmssBDS_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_withInt_(params_, [self getIndex] + 1)])) build];
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssBDS;", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder:);
  methods[1].selector = @selector(getUsagesRemaining);
  methods[2].selector = @selector(toByteArray);
  methods[3].selector = @selector(getIndex);
  methods[4].selector = @selector(getSecretKeySeed);
  methods[5].selector = @selector(getSecretKeyPRF);
  methods[6].selector = @selector(getPublicSeed);
  methods[7].selector = @selector(getRoot);
  methods[8].selector = @selector(getBDSState);
  methods[9].selector = @selector(getParameters);
  methods[10].selector = @selector(getNextKey);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LLibOrgBouncycastlePqcCryptoXmssXMSSParameters;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "secretKeySeed_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "secretKeyPRF_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "publicSeed_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "root_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "bdsState_", "LLibOrgBouncycastlePqcCryptoXmssBDS;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters = { "XMSSPrivateKeyParameters", "lib.org.bouncycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x11, 11, 6, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters;
}

@end

void LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *self, LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *builder) {
  LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_initWithBoolean_withNSString_(self, true, [((id<LibOrgBouncycastleCryptoDigest>) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSParameters *) nil_chk(((LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *) nil_chk(builder))->params_)) getDigest])) getAlgorithmName]);
  self->params_ = builder->params_;
  if (self->params_ == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"params == null");
  }
  jint n = [self->params_ getDigestSize];
  IOSByteArray *privateKey = builder->privateKey_;
  if (privateKey != nil) {
    if (builder->xmss_ == nil) {
      @throw new_JavaLangNullPointerException_initWithNSString_(@"xmss == null");
    }
    jint height = [self->params_ getHeight];
    jint indexSize = 4;
    jint secretKeySize = n;
    jint secretKeyPRFSize = n;
    jint publicSeedSize = n;
    jint rootSize = n;
    jint position = 0;
    jint index = LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(privateKey, position);
    if (!LibOrgBouncycastlePqcCryptoXmssXMSSUtil_isIndexValidWithInt_withLong_(height, index)) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"index out of bounds");
    }
    position += indexSize;
    self->secretKeySeed_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(privateKey, position, secretKeySize);
    position += secretKeySize;
    self->secretKeyPRF_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(privateKey, position, secretKeyPRFSize);
    position += secretKeyPRFSize;
    self->publicSeed_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(privateKey, position, publicSeedSize);
    position += publicSeedSize;
    self->root_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(privateKey, position, rootSize);
    position += rootSize;
    IOSByteArray *bdsStateBinary = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(privateKey, position, privateKey->size_ - position);
    @try {
      LibOrgBouncycastlePqcCryptoXmssBDS *bdsImport = (LibOrgBouncycastlePqcCryptoXmssBDS *) cast_chk(LibOrgBouncycastlePqcCryptoXmssXMSSUtil_deserializeWithByteArray_withIOSClass_(bdsStateBinary, LibOrgBouncycastlePqcCryptoXmssBDS_class_()), [LibOrgBouncycastlePqcCryptoXmssBDS class]);
      if ([((LibOrgBouncycastlePqcCryptoXmssBDS *) nil_chk(bdsImport)) getIndex] != index) {
        @throw new_JavaLangIllegalStateException_initWithNSString_(@"serialized BDS has wrong index");
      }
      self->bdsState_ = [bdsImport withWOTSDigestWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:LibOrgBouncycastlePqcCryptoXmssDigestUtil_getDigestOIDWithNSString_([((id<LibOrgBouncycastleCryptoDigest>) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSParameters *) nil_chk(builder->xmss_)) getDigest])) getAlgorithmName])];
    }
    @catch (JavaIoIOException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_withJavaLangThrowable_([e getMessage], e);
    }
    @catch (JavaLangClassNotFoundException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_withJavaLangThrowable_([e getMessage], e);
    }
  }
  else {
    IOSByteArray *tmpSecretKeySeed = builder->secretKeySeed_;
    if (tmpSecretKeySeed != nil) {
      if (tmpSecretKeySeed->size_ != n) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"size of secretKeySeed needs to be equal size of digest");
      }
      self->secretKeySeed_ = tmpSecretKeySeed;
    }
    else {
      self->secretKeySeed_ = [IOSByteArray newArrayWithLength:n];
    }
    IOSByteArray *tmpSecretKeyPRF = builder->secretKeyPRF_;
    if (tmpSecretKeyPRF != nil) {
      if (tmpSecretKeyPRF->size_ != n) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"size of secretKeyPRF needs to be equal size of digest");
      }
      self->secretKeyPRF_ = tmpSecretKeyPRF;
    }
    else {
      self->secretKeyPRF_ = [IOSByteArray newArrayWithLength:n];
    }
    IOSByteArray *tmpPublicSeed = builder->publicSeed_;
    if (tmpPublicSeed != nil) {
      if (tmpPublicSeed->size_ != n) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"size of publicSeed needs to be equal size of digest");
      }
      self->publicSeed_ = tmpPublicSeed;
    }
    else {
      self->publicSeed_ = [IOSByteArray newArrayWithLength:n];
    }
    IOSByteArray *tmpRoot = builder->root_;
    if (tmpRoot != nil) {
      if (tmpRoot->size_ != n) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"size of root needs to be equal size of digest");
      }
      self->root_ = tmpRoot;
    }
    else {
      self->root_ = [IOSByteArray newArrayWithLength:n];
    }
    LibOrgBouncycastlePqcCryptoXmssBDS *tmpBDSState = builder->bdsState_;
    if (tmpBDSState != nil) {
      self->bdsState_ = tmpBDSState;
    }
    else {
      if (builder->index_ < ((JreLShift32(1, [self->params_ getHeight])) - 2) && tmpPublicSeed != nil && tmpSecretKeySeed != nil) {
        self->bdsState_ = new_LibOrgBouncycastlePqcCryptoXmssBDS_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_withByteArray_withByteArray_withLibOrgBouncycastlePqcCryptoXmssOTSHashAddress_withInt_(self->params_, tmpPublicSeed, tmpSecretKeySeed, (LibOrgBouncycastlePqcCryptoXmssOTSHashAddress *) cast_chk([new_LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder_init() build], [LibOrgBouncycastlePqcCryptoXmssOTSHashAddress class]), builder->index_);
      }
      else {
        self->bdsState_ = new_LibOrgBouncycastlePqcCryptoXmssBDS_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_withInt_(self->params_, builder->index_);
      }
    }
  }
}

LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *builder) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters, initWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_, builder)
}

LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *builder) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters, initWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_, builder)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters)

@implementation LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder

- (instancetype)initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)params {
  LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_(self, params);
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *)withIndexWithInt:(jint)val {
  index_ = val;
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *)withSecretKeySeedWithByteArray:(IOSByteArray *)val {
  secretKeySeed_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(val);
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *)withSecretKeyPRFWithByteArray:(IOSByteArray *)val {
  secretKeyPRF_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(val);
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *)withPublicSeedWithByteArray:(IOSByteArray *)val {
  publicSeed_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(val);
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *)withRootWithByteArray:(IOSByteArray *)val {
  root_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(val);
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *)withBDSStateWithLibOrgBouncycastlePqcCryptoXmssBDS:(LibOrgBouncycastlePqcCryptoXmssBDS *)valBDS {
  bdsState_ = valBDS;
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *)withPrivateKeyWithByteArray:(IOSByteArray *)privateKeyVal
                                               withLibOrgBouncycastlePqcCryptoXmssXMSSParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)xmssParameters {
  privateKey_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(privateKeyVal);
  xmss_ = xmssParameters;
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *)build {
  return new_LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder;", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder;", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder;", 0x1, 5, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder;", 0x1, 6, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder;", 0x1, 7, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder;", 0x1, 8, 9, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder;", 0x1, 10, 11, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters:);
  methods[1].selector = @selector(withIndexWithInt:);
  methods[2].selector = @selector(withSecretKeySeedWithByteArray:);
  methods[3].selector = @selector(withSecretKeyPRFWithByteArray:);
  methods[4].selector = @selector(withPublicSeedWithByteArray:);
  methods[5].selector = @selector(withRootWithByteArray:);
  methods[6].selector = @selector(withBDSStateWithLibOrgBouncycastlePqcCryptoXmssBDS:);
  methods[7].selector = @selector(withPrivateKeyWithByteArray:withLibOrgBouncycastlePqcCryptoXmssXMSSParameters:);
  methods[8].selector = @selector(build);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LLibOrgBouncycastlePqcCryptoXmssXMSSParameters;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "index_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "secretKeySeed_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "secretKeyPRF_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "publicSeed_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "root_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "bdsState_", "LLibOrgBouncycastlePqcCryptoXmssBDS;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "privateKey_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "xmss_", "LLibOrgBouncycastlePqcCryptoXmssXMSSParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcCryptoXmssXMSSParameters;", "withIndex", "I", "withSecretKeySeed", "[B", "withSecretKeyPRF", "withPublicSeed", "withRoot", "withBDSState", "LLibOrgBouncycastlePqcCryptoXmssBDS;", "withPrivateKey", "[BLLibOrgBouncycastlePqcCryptoXmssXMSSParameters;", "LLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder = { "Builder", "lib.org.bouncycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x9, 9, 9, 12, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder;
}

@end

void LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *self, LibOrgBouncycastlePqcCryptoXmssXMSSParameters *params) {
  NSObject_init(self);
  self->index_ = 0;
  self->secretKeySeed_ = nil;
  self->secretKeyPRF_ = nil;
  self->publicSeed_ = nil;
  self->root_ = nil;
  self->bdsState_ = nil;
  self->privateKey_ = nil;
  self->xmss_ = nil;
  self->params_ = params;
}

LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *new_LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder, initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_, params)
}

LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder *create_LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder, initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_Builder)