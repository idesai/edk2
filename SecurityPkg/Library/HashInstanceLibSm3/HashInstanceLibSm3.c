/** @file
  This library is BaseCrypto SM3 hash instance.
  It can be registered to BaseCrypto router, to serve as hash engine.

Copyright (c) 2013 - 2018, Intel Corporation. All rights reserved. <BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <PiPei.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/HashLib.h>

/**
  The function set SM3 to digest list.

  @param DigestList   digest list
  @param Sm3Digest SM3 digest
**/
VOID
Tpm2SetSm3ToDigestList (
  IN TPML_DIGEST_VALUES *DigestList,
  IN UINT8              *Sm3Digest
  )
{
  DigestList->count = 1;
  DigestList->digests[0].hashAlg = TPM_ALG_SM3_256;
  CopyMem (
    DigestList->digests[0].digest.sm3_256,
    Sm3Digest,
    SM3_256_DIGEST_SIZE
    );
}

/**
  Start hash sequence.

  @param HashHandle Hash handle.

  @retval EFI_SUCCESS          Hash sequence start and HandleHandle returned.
  @retval EFI_OUT_OF_RESOURCES No enough resource to start hash.
**/
EFI_STATUS
EFIAPI
Sm3HashInit (
  OUT HASH_HANDLE    *HashHandle
  )
{
  VOID     *Sm3Ctx;
  UINTN    CtxSize;

  CtxSize = Sm3GetContextSize ();
  Sm3Ctx = AllocatePool (CtxSize);
  ASSERT (Sm3Ctx != NULL);

  Sm3Init (Sm3Ctx);

  *HashHandle = (HASH_HANDLE)Sm3Ctx;

  return EFI_SUCCESS;
}

/**
  Update hash sequence data.

  @param HashHandle    Hash handle.
  @param DataToHash    Data to be hashed.
  @param DataToHashLen Data size.

  @retval EFI_SUCCESS     Hash sequence updated.
**/
EFI_STATUS
EFIAPI
Sm3HashUpdate (
  IN HASH_HANDLE    HashHandle,
  IN VOID           *DataToHash,
  IN UINTN          DataToHashLen
  )
{
  VOID     *Sm3Ctx;

  Sm3Ctx = (VOID *)HashHandle;
  Sm3Update (Sm3Ctx, DataToHash, DataToHashLen);

  return EFI_SUCCESS;
}

/**
  Complete hash sequence complete.

  @param HashHandle    Hash handle.
  @param DigestList    Digest list.

  @retval EFI_SUCCESS     Hash sequence complete and DigestList is returned.
**/
EFI_STATUS
EFIAPI
Sm3HashFinal (
  IN HASH_HANDLE         HashHandle,
  OUT TPML_DIGEST_VALUES *DigestList
  )
{
  UINT8         Digest[SM3_256_DIGEST_SIZE];
  VOID          *Sm3Ctx;

  Sm3Ctx = (VOID *)HashHandle;
  Sm3Final (Sm3Ctx, Digest);

  FreePool (Sm3Ctx);

  Tpm2SetSm3ToDigestList (DigestList, Digest);

  return EFI_SUCCESS;
}

HASH_INTERFACE  mSm3InternalHashInstance = {
  HASH_ALGORITHM_SM3_256_GUID,
  Sm3HashInit,
  Sm3HashUpdate,
  Sm3HashFinal,
};

/**
  The function register SM3 instance.

  @retval EFI_SUCCESS   SM3 instance is registered, or system dose not support register SM3 instance
**/
EFI_STATUS
EFIAPI
HashInstanceLibSm3Constructor (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = RegisterHashInterfaceLib (&mSm3InternalHashInstance);
  if ((Status == EFI_SUCCESS) || (Status == EFI_UNSUPPORTED)) {
    //
    // Unsupported means platform policy does not need this instance enabled.
    //
    return EFI_SUCCESS;
  }
  return Status;
}
