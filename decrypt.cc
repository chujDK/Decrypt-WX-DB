#include "decrypt.h"
#include <Windows.h>
#include <cstdio>
#include <string>
#include <winerror.h>

#define SQLITE_HAS_CODEC 1

struct sqlite3;

typedef int (*sqlite3_open_ptr)(const char *, sqlite3 **);
typedef int (*sqlite3_close_ptr)(sqlite3 *);
typedef int(__fastcall *sqlite3_key_v2_ptr)(sqlite3 *, int, void *, size_t);
typedef int (*sqlite3_exec_ptr)(sqlite3 *, const char *, void *, void *,
                                char **);

static int simpleCallback(void *data, int argc, char **argv, char **azColName) {
  int i;
  fprintf(stderr, "%s: ", (const char *)data);
  for (i = 0; i < argc; i++) {
    printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
  }
  printf("\n");
  return 0;
}

using u8 = UINT8;
using u16 = UINT16;
using i16 = INT16;
using u32 = size_t;
using i64 = INT64;
using Pgno = u32;
struct Pager {
  void *pVfs;       /* OS functions to use for IO */
  u8 exclusiveMode; /* Boolean. True if locking_mode==EXCLUSIVE */
  u8 journalMode;   /* One of the PAGER_JOURNALMODE_* values */
  u8 useJournal;    /* Use a rollback journal on this file */
  u8 noSync;        /* Do not sync the journal if true */
  u8 fullSync;      /* Do extra syncs of the journal for robustness */
  u8 extraSync;     /* sync directory after journal delete */
  u8 syncFlags;     /* SYNC_NORMAL or SYNC_FULL otherwise */
  u8 walSyncFlags;  /* See description above */
  u8 tempFile;      /* zFilename is a temporary or immutable file */
  u8 noLock;        /* Do not lock (except in WAL mode) */
  u8 readOnly;      /* True for a read-only database */
  u8 memDb;         /* True to inhibit all file I/O */

  /**************************************************************************
  ** The following block contains those class members that change during
  ** routine operation.  Class members not in this block are either fixed
  ** when the pager is first created or else only change when there is a
  ** significant mode change (such as changing the page_size, locking_mode,
  ** or the journal_mode).  From another view, these class members describe
  ** the "state" of the pager, while other class members describe the
  ** "configuration" of the pager.
  */
  u8 eState;            /* Pager state (OPEN, READER, WRITER_LOCKED..) */
  u8 eLock;             /* Current lock held on database file */
  u8 changeCountDone;   /* Set after incrementing the change-counter */
  u8 setMaster;         /* True if a m-j name has been written to jrnl */
  u8 doNotSpill;        /* Do not spill the cache when non-zero */
  u8 subjInMemory;      /* True to use in-memory sub-journals */
  u8 bUseFetch;         /* True to use xFetch() */
  u8 hasHeldSharedLock; /* True if a shared lock has ever been held */
  Pgno dbSize;          /* Number of pages in the database */
  Pgno dbOrigSize;      /* dbSize before the current transaction */
  Pgno dbFileSize;      /* Number of pages in the database file */
  Pgno dbHintSize;      /* Value passed to FCNTL_SIZE_HINT call */
  int errCode;          /* One of several kinds of errors */
  int nRec;             /* Pages journalled since last j-header written */
  u32 cksumInit;        /* Quasi-random value added to every checksum */
  u32 nSubRec;          /* Number of records written to sub-journal */
  void *pInJournal;     /* One bit for each page in the database file */
  void *fd;             /* File descriptor for database */
  void *jfd;            /* File descriptor for main journal */
  void *sjfd;           /* File descriptor for sub-journal */
  i64 journalOff;       /* Current write offset in the journal file */
  i64 journalHdr;       /* Byte offset to previous journal header */
  void *pBackup;        /* Pointer to list of ongoing backup processes */
  void *aSavepoint;     /* Array of active savepoints */
  int nSavepoint;       /* Number of elements in aSavepoint[] */
  u32 iDataVersion;     /* Changes whenever database content changes */
  char dbFileVers[16];  /* Changes whenever database file changes */

  int nMmapOut;        /* Number of mmap pages currently outstanding */
  INT64 szMmap;        /* Desired maximum mmap size */
  void *pMmapFreelist; /* List of free mmap page headers (pDirty) */
  /*
  ** End of the routinely-changing class members
  ***************************************************************************/

  u16 nExtra;                  /* Add this many bytes to each in-memory page */
  i16 nReserve;                /* Number of unused bytes at end of each page */
  u32 vfsFlags;                /* Flags for sqlite3_vfs.xOpen() */
  u32 sectorSize;              /* Assumed sector size during rollback */
  int pageSize;                /* Number of bytes in a page */
  Pgno mxPgno;                 /* Maximum allowed size of the database */
  i64 journalSizeLimit;        /* Size limit for persistent journal files */
  char *zFilename;             /* Name of the database file */
  char *zJournal;              /* Name of the journal file */
  int (*xBusyHandler)(void *); /* Function to call when busy */
  void *pBusyHandlerArg;       /* Context argument for xBusyHandler */
  int aStat[4];                /* Total cache hits, misses, writes, spills */
#ifdef SQLITE_TEST
  int nRead; /* Database pages read */
#endif
  void (*xReiniter)(void *); /* Call this routine when reloading pages */
  int (*xGet)(Pager *, Pgno, void **, int); /* Routine to fetch a patch */
#ifdef SQLITE_HAS_CODEC
  void *(*xCodec)(void *, void *, Pgno, int); /* Routine for en/decoding data */
  void (*xCodecSizeChng)(void *, int, int);   /* Notify of page size changes */
  void (*xCodecFree)(void *);                 /* Destructor for the codec */
  void *pCodec; /* First argument to xCodec... methods */
#endif
  char *pTmpSpace; /* Pager.pageSize bytes of space for tmp use */
  void *pPCache;   /* Pointer to page cache object */
#ifndef SQLITE_OMIT_WAL
  void *pWal; /* Write-ahead log used by "journal_mode=wal" */
  char *zWal; /* File name for write-ahead log */
#endif
};



struct codec_ctx {
  int store_pass;              // 0
  int kdf_iter;                // 0xFA00
  int fast_kdf_iter;           // 0x2
  int kdf_salt_sz;             // 0x10
  int key_sz;                  // 0x20
  int iv_sz;                   // 0x10
  int block_sz;                // 0x10
  int page_sz;                 // 0x1000
  int keyspec_sz;              // 0x63
  int reserve_sz;              // 0x30
  int hmac_sz;                 // 0x14
  int plaintext_header_sz;     // 0
  int hmac_algorithm;          // 0
  int kdf_algorithm;           // 0
  unsigned int skip_read_hmac; // 0
  unsigned int need_kdf_salt;  // 0
  unsigned int flags;          // 3
  unsigned char *kdf_salt;
  unsigned char *hmac_kdf_salt;
  unsigned char *buffer;
  void *pBt;
  struct cipher_ctx *read_ctx;
  struct cipher_ctx *write_ctx;
  void *provider;
  void *provider_ctx;
};

int DecryptWXDB(const char *szFile, const char *szOutput, struct cipher_ctx *ctx) {
  sqlite3 *db;
  int nKey = 0x20;
  const char* key = "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA";
  bool decrypted = true;

  HINSTANCE hWXDll = LoadLibrary(TEXT("WeChatWin.dll"));
  if (hWXDll == NULL) {
    int err = GetLastError();
    printf("[-] open WeChatWin.dll failed %d\n", err);
    exit(0);
  }
  size_t WeChatWinDllBase = (size_t)GetModuleHandle(TEXT("WeChatWin.dll"));
  printf("[+] dll WeChatWin base: 0x%x\n", WeChatWinDllBase);

  sqlite3_open_ptr wx_sqlite3_open;
  sqlite3_close_ptr wx_sqlite3_close;
  sqlite3_key_v2_ptr wx_sqlite3_key_v2;
  sqlite3_exec_ptr wx_sqlite3_exec;
  wx_sqlite3_open = (sqlite3_open_ptr)(WeChatWinDllBase + 0x1450520);
  wx_sqlite3_close = (sqlite3_close_ptr)(WeChatWinDllBase + 0x144D8F0);
  wx_sqlite3_key_v2 = (sqlite3_key_v2_ptr)(WeChatWinDllBase + 0x13D2710);
  wx_sqlite3_exec = (sqlite3_exec_ptr)(WeChatWinDllBase + 0x141BDF0);

  char *zErrMsg = 0;
  int rc;
  const char *sql[0x10] = {0};
  const char *data = "Callback function called";

  rc = (*wx_sqlite3_open)(szFile, &db);
  if (rc) {
    fprintf(stderr, "Can't open database\n");
    exit(-1);
  } else {
    fprintf(stderr, "Opened database successfully\n");
  }

  sql[0] = "PRAGMA cipher_page_size = 4096;";
  sql[1] = "PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA1;";
  sql[2] = "PRAGMA cipher_default_hmac_algorithm = HMAC_SHA1;";
  sql[3] = "PRAGMA cipher_default_kdf_iter = 64000;";

  for (int i = 0; sql[i] != nullptr; i++) {
    rc = (*wx_sqlite3_exec)(db, sql[i], simpleCallback, (void *)data, &zErrMsg);
    if (rc != 0) {
      fprintf(stderr, "[%s] exec failed error: %s\n", sql[i], zErrMsg);
    } else {
      fprintf(stdout, "[%s] exec successed\n", sql[i]);
    }
  }
#ifdef VERBOSE
  printf("[+] db address: 0x%x\n", (size_t)db);
  printf("[+] table name: %s\n", (char *)(((size_t **)db)[4])[0]);
  printf("[+] Btree address: 0x%x\n", (((size_t **)db)[4])[1]);
#endif
  
  size_t *bTree_pBt = (((size_t ***)db)[4])[1];
  size_t *btShared_pBt = (size_t *)bTree_pBt[1];
  if ((size_t)btShared_pBt[1] != (size_t)db) {
    printf("[-] pBt not found\n");
    exit(-1);
  }
  Pager *pPager = (Pager *)btShared_pBt[0];
  size_t key_addr = (size_t)&key;
#ifdef VERBOSE
  printf("[!] pVfs->name = %s\n", (char *)((size_t *)pPager->pVfs)[4]);
#endif // VERBOSE
  // use the sqlite3_key_v2 to init
  __asm {
		xor edx, edx
		mov ecx, db
		mov esi, nKey
		push esi
		mov esi, key_addr
		push esi
		mov esi, [wx_sqlite3_key_v2]
		call esi
		add esp, 8
  }
#ifdef VERBOSE
  printf("[!] offset to xCodec: 0x%x\n",
         (size_t)((size_t)&pPager->xCodec - (size_t)pPager));
  printf("[!] offset to pCodec: 0x%x\n",
         (size_t)((size_t)&pPager->pCodec - (size_t)pPager));
  printf("[+] xCodec = 0x%x\n", (size_t)pPager->xCodec);
  printf("[+] pCodec = 0x%x\n", (size_t)pPager->pCodec);

  codec_ctx *pCodec = (codec_ctx *)pPager->pCodec;
  for (int i = 0; i * 4 < 0x54; i++) {
    printf("0x%x\n", ((size_t *)pCodec)[i]);
  }
  printf("[!] offset to pBt: 0x%x\n",
         (size_t)((size_t)&pCodec->pBt - (size_t)pCodec));
  if (pCodec->pBt != bTree_pBt) {
    printf("[-] codec_ctx not found\n");
    exit(-1);
  }
  printf("[+] codec_ctx addr: 0x%x\n", (size_t)pCodec);
  printf("[+] sqlcipher_provider addr: 0x%x\n", (size_t)pCodec->provider);

  cipher_ctx *read_ctx = pCodec->read_ctx;
  printf("[info] read_ctx: address: 0x%x\n", (size_t)read_ctx);
  printf("\tderive_key:\t%d\n", read_ctx->derive_key);
  printf("\tpass_sz:\t%d\n", read_ctx->pass_sz);
  printf("\tkey:\n");
  putchar('\t');
  for (int i = 0; i < read_ctx->pass_sz; i++) {
    printf("%02hhx", read_ctx->key[i]);
  }
  putchar('\n');
  printf("\thmac_key:\n");
  putchar('\t');
  for (int i = 0; i < read_ctx->pass_sz; i++) {
    printf("%02hhx", read_ctx->hmac_key[i]);
  }
  putchar('\n');

  printf("\tpass:\n");
  putchar('\t');
  for (int i = 0; i < read_ctx->pass_sz; i++) {
    printf("%02hhx", read_ctx->pass[i]);
  }
  putchar('\n');
  printf("\tkeyspec: 0x%x\n", (size_t)read_ctx->keyspec);

  if (rc) {
    fprintf(stderr, "[decode] Operation failed\n");
    exit(-1);
  } else {
    fprintf(stderr, "[decode] Operation finished\n");
  }
#endif // VERBOSE

  // replace the read_ctx
  codec_ctx *pCodec = (codec_ctx *)pPager->pCodec;
  if (pCodec->pBt != bTree_pBt) {
    printf("[-] codec_ctx not found\n");
    exit(-1);
  }
  pCodec->read_ctx = ctx;
//  pCodec->write_ctx = ctx;

  memset(sql, 0, sizeof(sql));
  sql[0] = _strdup((std::string("ATTACH DATABASE '") + szOutput +
                    std::string("' AS plaintext KEY '';"))
                       .c_str());
  sql[1] = "SELECT sqlcipher_export('plaintext');";
  sql[2] = "DETACH DATABASE plaintext;";

  for (int i = 0; sql[i] != nullptr; i++) {
    rc = (*wx_sqlite3_exec)(db, sql[i], simpleCallback, (void *)data, &zErrMsg);
    if (rc != 0) {
      fprintf(stderr, "[%s] exec failed error: %s\n", sql[i], zErrMsg);
      decrypted = false;
      // FIXME: here i didn't free the zErrMsg with sqlite3_free();
    } else {
      fprintf(stdout, "[%s] exec successed\n", sql[i]);
    }
  }

  free((void *)sql[0]);
  wx_sqlite3_close(db);
  return decrypted;
}