#include "keychain_darwin.h"
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

// Helper function for manual biometric authentication
// Returns 0 on success, or an error code otherwise
static int perform_biometric_auth(const char *reason_str) {
    LAContext *context = [[LAContext alloc] init];
    context.localizedFallbackTitle = @""; // Disable password fallback
    
    NSString *reason = [NSString stringWithUTF8String:reason_str];
    if ([reason length] == 0) {
        reason = @"Authentication required";
    }

    __block BOOL authSuccess = NO;
    __block int errorCode = 0;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
             localizedReason:reason
                       reply:^(BOOL success, NSError *error) {
        authSuccess = success;
        if (!success) {
            errorCode = (int)error.code;
        }
        dispatch_semaphore_signal(sema);
    }];
    
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    
    if (authSuccess) return 0;
    return errorCode;
}

static char* get_auth_error_message(int code) {
    if (code == LAErrorUserCancel || code == LAErrorSystemCancel || code == -128) {
        return strdup("User canceled authentication");
    }
    return strdup([[NSString stringWithFormat:@"Authentication failed (error %d)", code] UTF8String]);
}

KeychainResult keychain_set(const char *service, const char *account,
                            const char *data, size_t length,
                            bool require_biometrics) {
  KeychainResult result = {NULL, 0, NULL};

  if (require_biometrics) {
      int authCode = perform_biometric_auth("Authentication required to save secret");
      if (authCode != 0) {
          result.error = get_auth_error_message(authCode);
          return result;
      }
  }

  NSString *serviceNS = [NSString stringWithUTF8String:service];
  NSString *accountNS = [NSString stringWithUTF8String:account];
  NSData *dataNS = [NSData dataWithBytes:data length:length];

  NSMutableDictionary *query = [NSMutableDictionary dictionary];
  query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  query[(__bridge id)kSecAttrService] = serviceNS;
  query[(__bridge id)kSecAttrAccount] = accountNS;

  // Delete existing item first
  SecItemDelete((__bridge CFDictionaryRef)query);

  query[(__bridge id)kSecAttrAccessible] =
      (__bridge id)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly;
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

  if (use_biometrics) {
      int authCode = perform_biometric_auth(prompt ? prompt : "Authentication required to retrieve secret");
      if (authCode != 0) {
          result.error = get_auth_error_message(authCode);
          return result;
      }
  }

  NSString *serviceNS = [NSString stringWithUTF8String:service];
  NSString *accountNS = [NSString stringWithUTF8String:account];

  NSMutableDictionary *query = [NSMutableDictionary dictionary];
  query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  query[(__bridge id)kSecAttrService] = serviceNS;
  query[(__bridge id)kSecAttrAccount] = accountNS;
  query[(__bridge id)kSecReturnData] = @YES;

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

  if (use_biometrics) {
      int authCode = perform_biometric_auth(prompt ? prompt : "Authentication required to delete secret");
      if (authCode != 0) {
          result.error = get_auth_error_message(authCode);
          return result;
      }
  }

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

  if (use_biometrics) {
      int authCode = perform_biometric_auth(prompt ? prompt : "Authentication required to list secrets");
      if (authCode != 0) {
          result.error = get_auth_error_message(authCode);
          return result;
      }
  }

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
