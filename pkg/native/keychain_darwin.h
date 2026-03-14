#ifndef KEYCHAIN_H
#define KEYCHAIN_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
  char *data;
  size_t length;
  char *error;
} KeychainResult;

typedef struct {
  char **keys;
  int count;
  char *error;
} KeychainListResult;

KeychainResult keychain_set(const char *service, const char *account,
                            const char *data, size_t length,
                            bool require_biometrics);
KeychainResult keychain_get(const char *service, const char *account,
                            bool use_biometrics, const char *prompt);
KeychainResult keychain_delete(const char *service, const char *account,
                               bool use_biometrics, const char *prompt);
KeychainListResult keychain_list(const char *service, bool use_biometrics,
                                 const char *prompt);

void free_keychain_result(KeychainResult result);
void free_keychain_list_result(KeychainListResult result);

#endif
