#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

AuthorizationRef* create_auth_ref_ptr();

OSStatus request_auth(
    char *right_name,
    char *prompt, size_t prompt_size,
    AuthorizationRef* ref_ptr);

OSStatus destroy_auth(AuthorizationRef* ref_ptr);
