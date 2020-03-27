//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/SimpleLookupTable.java
//

#include "ECPoint.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "SimpleLookupTable.h"

@interface LibOrgBouncycastleMathEcSimpleLookupTable () {
 @public
  IOSObjectArray *points_;
}

+ (IOSObjectArray *)copy__WithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points
                                                           withInt:(jint)off
                                                           withInt:(jint)len OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcSimpleLookupTable, points_, IOSObjectArray *)

__attribute__((unused)) static IOSObjectArray *LibOrgBouncycastleMathEcSimpleLookupTable_copy__WithLibOrgBouncycastleMathEcECPointArray_withInt_withInt_(IOSObjectArray *points, jint off, jint len);

@implementation LibOrgBouncycastleMathEcSimpleLookupTable

+ (IOSObjectArray *)copy__WithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points
                                                           withInt:(jint)off
                                                           withInt:(jint)len {
  return LibOrgBouncycastleMathEcSimpleLookupTable_copy__WithLibOrgBouncycastleMathEcECPointArray_withInt_withInt_(points, off, len);
}

- (instancetype)initWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points
                                                     withInt:(jint)off
                                                     withInt:(jint)len {
  LibOrgBouncycastleMathEcSimpleLookupTable_initWithLibOrgBouncycastleMathEcECPointArray_withInt_withInt_(self, points, off, len);
  return self;
}

- (jint)getSize {
  return ((IOSObjectArray *) nil_chk(points_))->size_;
}

- (LibOrgBouncycastleMathEcECPoint *)lookupWithInt:(jint)index {
  return IOSObjectArray_Get(nil_chk(points_), index);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "[LLibOrgBouncycastleMathEcECPoint;", 0xa, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(copy__WithLibOrgBouncycastleMathEcECPointArray:withInt:withInt:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleMathEcECPointArray:withInt:withInt:);
  methods[2].selector = @selector(getSize);
  methods[3].selector = @selector(lookupWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "points_", "[LLibOrgBouncycastleMathEcECPoint;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "copy", "[LLibOrgBouncycastleMathEcECPoint;II", "lookup", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcSimpleLookupTable = { "SimpleLookupTable", "lib.org.bouncycastle.math.ec", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcSimpleLookupTable;
}

@end

IOSObjectArray *LibOrgBouncycastleMathEcSimpleLookupTable_copy__WithLibOrgBouncycastleMathEcECPointArray_withInt_withInt_(IOSObjectArray *points, jint off, jint len) {
  LibOrgBouncycastleMathEcSimpleLookupTable_initialize();
  IOSObjectArray *result = [IOSObjectArray newArrayWithLength:len type:LibOrgBouncycastleMathEcECPoint_class_()];
  for (jint i = 0; i < len; ++i) {
    (void) IOSObjectArray_Set(result, i, IOSObjectArray_Get(nil_chk(points), off + i));
  }
  return result;
}

void LibOrgBouncycastleMathEcSimpleLookupTable_initWithLibOrgBouncycastleMathEcECPointArray_withInt_withInt_(LibOrgBouncycastleMathEcSimpleLookupTable *self, IOSObjectArray *points, jint off, jint len) {
  NSObject_init(self);
  self->points_ = LibOrgBouncycastleMathEcSimpleLookupTable_copy__WithLibOrgBouncycastleMathEcECPointArray_withInt_withInt_(points, off, len);
}

LibOrgBouncycastleMathEcSimpleLookupTable *new_LibOrgBouncycastleMathEcSimpleLookupTable_initWithLibOrgBouncycastleMathEcECPointArray_withInt_withInt_(IOSObjectArray *points, jint off, jint len) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcSimpleLookupTable, initWithLibOrgBouncycastleMathEcECPointArray_withInt_withInt_, points, off, len)
}

LibOrgBouncycastleMathEcSimpleLookupTable *create_LibOrgBouncycastleMathEcSimpleLookupTable_initWithLibOrgBouncycastleMathEcECPointArray_withInt_withInt_(IOSObjectArray *points, jint off, jint len) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcSimpleLookupTable, initWithLibOrgBouncycastleMathEcECPointArray_withInt_withInt_, points, off, len)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcSimpleLookupTable)
