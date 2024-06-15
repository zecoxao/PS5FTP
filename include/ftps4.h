#include "resolve.h"



void ftp_init(const char *ip, unsigned short int port);
void ftp_fini();

struct tailored_offsets
{
    uint64_t offset_dmpml4i;
    uint64_t offset_dmpdpi;
    uint64_t offset_pml4pml4i;
    uint64_t offset_mailbox_base;
    uint64_t offset_mailbox_flags;
    uint64_t offset_mailbox_meta;
    uint64_t offset_authmgr_handle;
    uint64_t offset_sbl_sxlock;
    uint64_t offset_sbl_mb_mtx;
    uint64_t offset_datacave_1;
    uint64_t offset_datacave_2;
};


int sock;
uint64_t authmgr_handle;
struct tailored_offsets offsets;