//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/StringList.java
//

#include "J2ObjC_source.h"
#include "StringList.h"

@interface LibOrgBouncycastleUtilStringList : NSObject

@end

@implementation LibOrgBouncycastleUtilStringList

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "Z", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x401, 2, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LNSString;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LNSString;", 0x401, 4, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(addWithNSString:);
  methods[1].selector = @selector(getWithInt:);
  methods[2].selector = @selector(size);
  methods[3].selector = @selector(toStringArray);
  methods[4].selector = @selector(toStringArrayWithInt:withInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "add", "LNSString;", "get", "I", "toStringArray", "II", "Ljava/lang/Object;Llib/org/bouncycastle/util/Iterable<Ljava/lang/String;>;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilStringList = { "StringList", "lib.org.bouncycastle.util", ptrTable, methods, NULL, 7, 0x609, 5, 0, -1, -1, -1, 6, -1 };
  return &_LibOrgBouncycastleUtilStringList;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilStringList)
