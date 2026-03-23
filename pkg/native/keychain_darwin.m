#include "keychain_darwin.h"
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

KeychainResult keychain_set(const char *service, const char *account,
                            const char *data, size_t length,
                            bool require_biometrics) {
  KeychainResult result = {NULL, 0, NULL};

  NSString *serviceNS = [NSString stringWithUTF8String:service];
  NSString *accountNS = [NSString stringWithUTF8String:account];
  NSData *dataNS = [NSData dataWithBytes:data length:length];

  NSMutableDictionary *query = [NSMutableDictionary dictionary];
  query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  query[(__bridge id)kSecAttrService] = serviceNS;
  query[(__bridge id)kSecAttrAccount] = accountNS;

  // Delete existing item first to ensure update
  SecItemDelete((__bridge CFDictionaryRef)query);

  if (require_biometrics) {
    LAContext *context = [[LAContext alloc] init];
    context.localizedFallbackTitle = @"";
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    __block BOOL success = NO;

    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:@"Authentication required to save secret"
                      reply:^(BOOL s, NSError *e) {
                        success = s;
                        dispatch_semaphore_signal(sema);
                      }];

    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

    if (!success) {
      result.error = strdup("Authentication failed");
      return result;
    }
  }

  query[(__bridge id)kSecAttrAccessible] =
      (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
  query[(__bridge id)kSecValueData] = dataNS;

  OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
  if (status != errSecSuccess) {
    result.error =
        strdup([[NSString stringWithFormat:@"Failed to add keychain item: %d",
                                           (int)status] UTF8String]);
  }

  return result;
}

KeychainResult keychain_get(const char *service, const char *account,
                            bool use_biometrics, const char *prompt) {
  KeychainResult result = {NULL, 0, NULL};

  NSString *serviceNS = [NSString stringWithUTF8String:service];
  NSString *accountNS = [NSString stringWithUTF8String:account];
  NSString *promptNS = [NSString stringWithUTF8String:prompt];

  LAContext *context = nil;
  if (use_biometrics || [promptNS length] > 0) {
    context = [[LAContext alloc] init];
    context.localizedFallbackTitle = @"";

    NSString *reason = promptNS;
    if ([reason length] == 0) {
      reason = @"Authentication required to retrieve secret";
    }

    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    __block BOOL success = NO;

    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:reason
                      reply:^(BOOL s, NSError *e) {
                        success = s;
                        dispatch_semaphore_signal(sema);
                      }];

    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

    if (!success) {
      result.error = strdup("Authentication failed");
      return result;
    }
  }

  NSMutableDictionary *query = [NSMutableDictionary dictionary];
  query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  query[(__bridge id)kSecAttrService] = serviceNS;
  query[(__bridge id)kSecAttrAccount] = accountNS;
  query[(__bridge id)kSecReturnData] = @YES;

  if (context != nil) {
    query[(__bridge id)kSecUseAuthenticationContext] = context;
  }

  CFTypeRef dataTypeRef = NULL;
  OSStatus status =
      SecItemCopyMatching((__bridge CFDictionaryRef)query, &dataTypeRef);

  if (status == errSecSuccess) {
    NSData *data = (__bridge NSData *)dataTypeRef;
    result.length = [data length];
    result.data = malloc(result.length);
    [data getBytes:result.data length:result.length];
    CFRelease(dataTypeRef);
  } else if (status == errSecItemNotFound) {
    result.error = strdup("Secret not found");
  } else if (status == -128) {
    result.error = strdup("User canceled authentication (OS-level prompt)");
  } else {
    result.error = strdup([[NSString
        stringWithFormat:@"Failed to retrieve keychain item: %d", (int)status]
        UTF8String]);
  }

  return result;
}

KeychainResult keychain_delete(const char *service, const char *account,
                               bool use_biometrics, const char *prompt) {
  KeychainResult result = {NULL, 0, NULL};

  NSString *serviceNS = [NSString stringWithUTF8String:service];
  NSString *accountNS = [NSString stringWithUTF8String:account];

  NSMutableDictionary *query = [NSMutableDictionary dictionary];
  query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  query[(__bridge id)kSecAttrService] = serviceNS;
  query[(__bridge id)kSecAttrAccount] = accountNS;

  OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
  if (status != errSecSuccess && status != errSecItemNotFound) {
    result.error = strdup([[NSString
        stringWithFormat:@"Failed to delete keychain item: %d", (int)status]
        UTF8String]);
  }

  return result;
}

KeychainListResult keychain_list(const char *service, bool use_biometrics,
                                 const char *prompt) {
  KeychainListResult result = {NULL, 0, NULL};

  NSString *serviceNS = [NSString stringWithUTF8String:service];

  NSMutableDictionary *query = [NSMutableDictionary dictionary];
  query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  query[(__bridge id)kSecAttrService] = serviceNS;
  query[(__bridge id)kSecReturnAttributes] = @YES;
  query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;

  CFTypeRef resultRef = NULL;
  OSStatus status =
      SecItemCopyMatching((__bridge CFDictionaryRef)query, &resultRef);

  if (status == errSecSuccess) {
    NSArray *items = (__bridge NSArray *)resultRef;
    result.count = (int)[items count];
    result.keys = malloc(sizeof(char *) * result.count);

    for (int i = 0; i < result.count; i++) {
      NSDictionary *item = items[i];
      NSString *account = item[(__bridge id)kSecAttrAccount];
      result.keys[i] = strdup([account UTF8String]);
    }
    CFRelease(resultRef);
  } else if (status == errSecItemNotFound) {
    result.count = 0;
    result.keys = NULL;
  } else {
    result.error =
        strdup([[NSString stringWithFormat:@"Failed to list keychain items: %d",
                                           (int)status] UTF8String]);
  }

  return result;
}

void free_keychain_result(KeychainResult result) {
  if (result.data) {
    // Zero out sensitive data before freeing
    memset(result.data, 0, result.length);
    free(result.data);
  }
  if (result.error)
    free(result.error);
}

void free_keychain_list_result(KeychainListResult result) {
  if (result.keys) {
    for (int i = 0; i < result.count; i++) {
      free(result.keys[i]);
    }
    free(result.keys);
  }
  if (result.error)
    free(result.error);
}
