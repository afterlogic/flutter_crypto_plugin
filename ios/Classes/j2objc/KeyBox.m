//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/gpg/keybox/KeyBox.java
//

#include "Blob.h"
#include "BlobType.h"
#include "BlobVerifier.h"
#include "FirstBlob.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyBlob.h"
#include "KeyBox.h"
#include "KeyBoxByteBuffer.h"
#include "KeyFingerPrintCalculator.h"
#include "java/io/IOException.h"
#include "java/io/InputStream.h"
#include "java/util/ArrayList.h"
#include "java/util/Collections.h"
#include "java/util/List.h"

@interface LibOrgBouncycastleGpgKeyboxKeyBox () {
 @public
  LibOrgBouncycastleGpgKeyboxFirstBlob *firstBlob_;
  id<JavaUtilList> keyBlobs_;
}

- (instancetype)initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer:(LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *)buffer
      withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)keyFingerPrintCalculator
                        withLibOrgBouncycastleGpgKeyboxBlobVerifier:(id<LibOrgBouncycastleGpgKeyboxBlobVerifier>)blobVerifier;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleGpgKeyboxKeyBox, firstBlob_, LibOrgBouncycastleGpgKeyboxFirstBlob *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleGpgKeyboxKeyBox, keyBlobs_, id<JavaUtilList>)

__attribute__((unused)) static void LibOrgBouncycastleGpgKeyboxKeyBox_initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(LibOrgBouncycastleGpgKeyboxKeyBox *self, LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *buffer, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> keyFingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier);

__attribute__((unused)) static LibOrgBouncycastleGpgKeyboxKeyBox *new_LibOrgBouncycastleGpgKeyboxKeyBox_initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *buffer, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> keyFingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleGpgKeyboxKeyBox *create_LibOrgBouncycastleGpgKeyboxKeyBox_initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *buffer, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> keyFingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier);

@implementation LibOrgBouncycastleGpgKeyboxKeyBox

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)input
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)keyFingerPrintCalculator
withLibOrgBouncycastleGpgKeyboxBlobVerifier:(id<LibOrgBouncycastleGpgKeyboxBlobVerifier>)blobVerifier {
  LibOrgBouncycastleGpgKeyboxKeyBox_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(self, input, keyFingerPrintCalculator, blobVerifier);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)encoding
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)keyFingerPrintCalculator
withLibOrgBouncycastleGpgKeyboxBlobVerifier:(id<LibOrgBouncycastleGpgKeyboxBlobVerifier>)blobVerifier {
  LibOrgBouncycastleGpgKeyboxKeyBox_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(self, encoding, keyFingerPrintCalculator, blobVerifier);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer:(LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *)buffer
      withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)keyFingerPrintCalculator
                        withLibOrgBouncycastleGpgKeyboxBlobVerifier:(id<LibOrgBouncycastleGpgKeyboxBlobVerifier>)blobVerifier {
  LibOrgBouncycastleGpgKeyboxKeyBox_initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(self, buffer, keyFingerPrintCalculator, blobVerifier);
  return self;
}

- (LibOrgBouncycastleGpgKeyboxFirstBlob *)getFirstBlob {
  return firstBlob_;
}

- (id<JavaUtilList>)getKeyBlobs {
  return keyBlobs_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, 1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, 1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleGpgKeyboxFirstBlob;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilList;", 0x1, -1, -1, -1, 4, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoInputStream:withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:withLibOrgBouncycastleGpgKeyboxBlobVerifier:);
  methods[1].selector = @selector(initWithByteArray:withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:withLibOrgBouncycastleGpgKeyboxBlobVerifier:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer:withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:withLibOrgBouncycastleGpgKeyboxBlobVerifier:);
  methods[3].selector = @selector(getFirstBlob);
  methods[4].selector = @selector(getKeyBlobs);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "firstBlob_", "LLibOrgBouncycastleGpgKeyboxFirstBlob;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "keyBlobs_", "LJavaUtilList;", .constantValue.asLong = 0, 0x12, -1, -1, 5, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoInputStream;LLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;LLibOrgBouncycastleGpgKeyboxBlobVerifier;", "LJavaIoIOException;", "[BLLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;LLibOrgBouncycastleGpgKeyboxBlobVerifier;", "LLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer;LLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;LLibOrgBouncycastleGpgKeyboxBlobVerifier;", "()Ljava/util/List<Llib/org/bouncycastle/gpg/keybox/KeyBlob;>;", "Ljava/util/List<Llib/org/bouncycastle/gpg/keybox/KeyBlob;>;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleGpgKeyboxKeyBox = { "KeyBox", "lib.org.bouncycastle.gpg.keybox", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleGpgKeyboxKeyBox;
}

@end

void LibOrgBouncycastleGpgKeyboxKeyBox_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(LibOrgBouncycastleGpgKeyboxKeyBox *self, JavaIoInputStream *input, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> keyFingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier) {
  LibOrgBouncycastleGpgKeyboxKeyBox_initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(self, LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_wrapWithId_(input), keyFingerPrintCalculator, blobVerifier);
}

LibOrgBouncycastleGpgKeyboxKeyBox *new_LibOrgBouncycastleGpgKeyboxKeyBox_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(JavaIoInputStream *input, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> keyFingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleGpgKeyboxKeyBox, initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_, input, keyFingerPrintCalculator, blobVerifier)
}

LibOrgBouncycastleGpgKeyboxKeyBox *create_LibOrgBouncycastleGpgKeyboxKeyBox_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(JavaIoInputStream *input, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> keyFingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleGpgKeyboxKeyBox, initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_, input, keyFingerPrintCalculator, blobVerifier)
}

void LibOrgBouncycastleGpgKeyboxKeyBox_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(LibOrgBouncycastleGpgKeyboxKeyBox *self, IOSByteArray *encoding, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> keyFingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier) {
  LibOrgBouncycastleGpgKeyboxKeyBox_initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(self, LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_wrapWithId_(encoding), keyFingerPrintCalculator, blobVerifier);
}

LibOrgBouncycastleGpgKeyboxKeyBox *new_LibOrgBouncycastleGpgKeyboxKeyBox_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(IOSByteArray *encoding, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> keyFingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleGpgKeyboxKeyBox, initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_, encoding, keyFingerPrintCalculator, blobVerifier)
}

LibOrgBouncycastleGpgKeyboxKeyBox *create_LibOrgBouncycastleGpgKeyboxKeyBox_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(IOSByteArray *encoding, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> keyFingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleGpgKeyboxKeyBox, initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_, encoding, keyFingerPrintCalculator, blobVerifier)
}

void LibOrgBouncycastleGpgKeyboxKeyBox_initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(LibOrgBouncycastleGpgKeyboxKeyBox *self, LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *buffer, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> keyFingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier) {
  NSObject_init(self);
  LibOrgBouncycastleGpgKeyboxBlob *blob = LibOrgBouncycastleGpgKeyboxBlob_getInstanceWithId_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(buffer, keyFingerPrintCalculator, blobVerifier);
  if (blob == nil) {
    @throw new_JavaIoIOException_initWithNSString_(@"No first blob, is the source zero length?");
  }
  if (!([blob isKindOfClass:[LibOrgBouncycastleGpgKeyboxFirstBlob class]])) {
    @throw new_JavaIoIOException_initWithNSString_(@"First blob is not KeyBox 'First Blob'.");
  }
  LibOrgBouncycastleGpgKeyboxFirstBlob *firstBlob = (LibOrgBouncycastleGpgKeyboxFirstBlob *) cast_chk(blob, [LibOrgBouncycastleGpgKeyboxFirstBlob class]);
  JavaUtilArrayList *keyBoxEntries = new_JavaUtilArrayList_init();
  for (LibOrgBouncycastleGpgKeyboxBlob *materialBlob = LibOrgBouncycastleGpgKeyboxBlob_getInstanceWithId_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(buffer, keyFingerPrintCalculator, blobVerifier); materialBlob != nil; materialBlob = LibOrgBouncycastleGpgKeyboxBlob_getInstanceWithId_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(buffer, keyFingerPrintCalculator, blobVerifier)) {
    if ([materialBlob getType] == JreLoadEnum(LibOrgBouncycastleGpgKeyboxBlobType, FIRST_BLOB)) {
      @throw new_JavaIoIOException_initWithNSString_(@"Unexpected second 'FirstBlob', there should only be one FirstBlob at the start of the file.");
    }
    [keyBoxEntries addWithId:(LibOrgBouncycastleGpgKeyboxKeyBlob *) cast_chk(materialBlob, [LibOrgBouncycastleGpgKeyboxKeyBlob class])];
  }
  self->firstBlob_ = firstBlob;
  self->keyBlobs_ = JavaUtilCollections_unmodifiableListWithJavaUtilList_(keyBoxEntries);
}

LibOrgBouncycastleGpgKeyboxKeyBox *new_LibOrgBouncycastleGpgKeyboxKeyBox_initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *buffer, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> keyFingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleGpgKeyboxKeyBox, initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_, buffer, keyFingerPrintCalculator, blobVerifier)
}

LibOrgBouncycastleGpgKeyboxKeyBox *create_LibOrgBouncycastleGpgKeyboxKeyBox_initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *buffer, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> keyFingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleGpgKeyboxKeyBox, initWithLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_, buffer, keyFingerPrintCalculator, blobVerifier)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleGpgKeyboxKeyBox)