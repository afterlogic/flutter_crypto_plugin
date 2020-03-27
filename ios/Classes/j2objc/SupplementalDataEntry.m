//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/SupplementalDataEntry.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "SupplementalDataEntry.h"

@implementation LibOrgBouncycastleCryptoTlsSupplementalDataEntry

- (instancetype)initWithInt:(jint)dataType
              withByteArray:(IOSByteArray *)data {
  LibOrgBouncycastleCryptoTlsSupplementalDataEntry_initWithInt_withByteArray_(self, dataType, data);
  return self;
}

- (jint)getDataType {
  return dataType_;
}

- (IOSByteArray *)getData {
  return data_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withByteArray:);
  methods[1].selector = @selector(getDataType);
  methods[2].selector = @selector(getData);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "dataType_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "data_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsSupplementalDataEntry = { "SupplementalDataEntry", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 3, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsSupplementalDataEntry;
}

@end

void LibOrgBouncycastleCryptoTlsSupplementalDataEntry_initWithInt_withByteArray_(LibOrgBouncycastleCryptoTlsSupplementalDataEntry *self, jint dataType, IOSByteArray *data) {
  NSObject_init(self);
  self->dataType_ = dataType;
  self->data_ = data;
}

LibOrgBouncycastleCryptoTlsSupplementalDataEntry *new_LibOrgBouncycastleCryptoTlsSupplementalDataEntry_initWithInt_withByteArray_(jint dataType, IOSByteArray *data) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsSupplementalDataEntry, initWithInt_withByteArray_, dataType, data)
}

LibOrgBouncycastleCryptoTlsSupplementalDataEntry *create_LibOrgBouncycastleCryptoTlsSupplementalDataEntry_initWithInt_withByteArray_(jint dataType, IOSByteArray *data) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsSupplementalDataEntry, initWithInt_withByteArray_, dataType, data)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsSupplementalDataEntry)