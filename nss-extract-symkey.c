/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>

#include "nss.h"
#include "pk11pub.h"
#include "prerror.h"
#include "secerr.h"

void printPRError(const char* message) {
  fprintf(stderr, "%s: %s\n", message, PR_ErrorToString(PR_GetError(), 0));
}

int main(int argc, char* argv[]) {
  if (NSS_Initialize(".", "", "", "", NSS_INIT_NOMODDB | NSS_INIT_NOROOTINIT)
        != SECSuccess) {
    printPRError("NSS_Initialize failed");
    return 1;
  }

  PK11SlotInfo* slot = PK11_GetInternalKeySlot();
  if (!slot) {
    printPRError("PK11_GetInternalKeySlot failed");
    return 1;
  }

  // Create a key to wrap the SDR key to export it.
  unsigned char wrappingKeyIDBytes[] = { 0 };
  SECItem wrappingKeyID = {
    siBuffer,
    wrappingKeyIDBytes,
    sizeof(wrappingKeyIDBytes)
  };
  PK11SymKey* wrappingKey = PK11_TokenKeyGen(slot, CKM_DES3_CBC, 0, 0,
                                             &wrappingKeyID, PR_FALSE, NULL);
  if (!wrappingKey) {
    printPRError("PK11_TokenKeyGen failed");
    return 1;
  }

  // This identifies the SDR key.
  unsigned char sdrKeyIDBytes[] = {
    0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
  };
  SECItem sdrKeyID = { siBuffer, sdrKeyIDBytes, sizeof(sdrKeyIDBytes) };
  PK11SymKey* sdrKey = PK11_FindFixedKey(slot, CKM_DES3_CBC, &sdrKeyID, NULL);
  if (!sdrKey) {
    printPRError("PK11_FindFixedKey failed");
    return 1;
  }

  // Wrap the SDR key.
  unsigned char wrappedKeyBuf[1024];
  SECItem wrapped = { siBuffer, wrappedKeyBuf, sizeof(wrappedKeyBuf) };
  if (PK11_WrapSymKey(CKM_DES3_ECB, NULL, wrappingKey, sdrKey, &wrapped)
        != SECSuccess) {
    printPRError("PK11_WrapSymKey failed");
    return 1;
  }

  // Unwrap the SDR key (NSS considers the SDR key "sensitive" and so won't just
  // export it as raw key material - we have to export it and then re-import it
  // as non-sensitive to get that data.
  PK11SymKey* unwrapped = PK11_UnwrapSymKey(wrappingKey, CKM_DES3_ECB, NULL,
                                            &wrapped, CKM_DES3_CBC, CKA_ENCRYPT,
                                            0);
  if (!unwrapped) {
    printPRError("PK11_UnwrapSymKey failed");
    return 1;
  }
  if (PK11_ExtractKeyValue(unwrapped) != SECSuccess) {
    printPRError("PK11_ExtractKeyValue failed");
    return 1;
  }
  SECItem* keyData = PK11_GetKeyData(unwrapped);
  if (!keyData) {
    printPRError("PK11_GetKeyData failed");
    return 1;
  }
  for (int i = 0; i < keyData->len; i++) {
    printf("0x%02hhx, ", keyData->data[i]);
  }
  printf("\n");

  PK11_FreeSymKey(unwrapped);
  PK11_FreeSymKey(sdrKey);
  PK11_FreeSymKey(wrappingKey);
  PK11_FreeSlot(slot);

  if (NSS_Shutdown() != SECSuccess) {
    printPRError("NSS_Shutdown failed");
    return 1;
  }
  return 0;
}
