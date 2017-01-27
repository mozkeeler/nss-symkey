/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>

#include "nss.h"
#include "pk11pub.h"
#include "prerror.h"
#include "secerr.h"
#include "secmod.h"

void printPRError(const char* message) {
  fprintf(stderr, "%s: %s\n", message, PR_ErrorToString(PR_GetError(), 0));
}

int main(int argc, char* argv[]) {
  if (NSS_Initialize("sql:.", "", "", "",
                     NSS_INIT_NOMODDB | NSS_INIT_NOROOTINIT) != SECSuccess) {
    printPRError("NSS_Initialize failed");
    return 1;
  }

  PK11SlotInfo* slot = PK11_GetInternalKeySlot();
  if (!slot) {
    printPRError("PK11_GetInternalKeySlot failed");
    return 1;
  }

  // These are the bytes of the SDR key from the previous step:
  unsigned char keyBytes[] = {
    0x70, 0xab, 0xea, 0x1f, 0x8f, 0xe3, 0x4a, 0x7a, 0xb5, 0xb0, 0x43, 0xe5,
    0x51, 0x83, 0x86, 0xe5, 0xb3, 0x43, 0xa8, 0x1f, 0xc1, 0x57, 0x86, 0x46
  };
  SECItem keyItem = { siBuffer, keyBytes, sizeof(keyBytes) };
  PK11SymKey* key = PK11_ImportSymKey(slot, CKM_DES3_CBC, PK11_OriginUnwrap,
                                      CKA_ENCRYPT, &keyItem, NULL);
  if (!key) {
    printPRError("PK11_ImportSymKey failed");
    return 1;
  }

  PK11_FreeSymKey(key);
  PK11_FreeSlot(slot);

  if (NSS_Shutdown() != SECSuccess) {
    printPRError("NSS_Shutdown failed");
    return 1;
  }
  return 0;
}
