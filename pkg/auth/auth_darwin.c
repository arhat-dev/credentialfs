#include <stdlib.h>
#include <string.h>

#include "auth_darwin.h"

AuthorizationRef *create_auth_ref_ptr()
{
    AuthorizationRef *ref_ptr = malloc(sizeof(AuthorizationRef));
    return ref_ptr;
}

OSStatus request_auth(
    char *right_name,
    char *prompt, size_t prompt_size,
    AuthorizationRef *ref_ptr)
{
    OSStatus code = AuthorizationCreate(
        NULL,
        kAuthorizationEmptyEnvironment,
        kAuthorizationFlagDefaults,
        ref_ptr);

    if (code != errAuthorizationSuccess)
    {
        free(right_name);
        free(prompt);

        // ref_ptr is created for this function call,
        // and since the authorization failed,
        // it will never be used
        free(ref_ptr);

        return code;
    }

    AuthorizationItem rightItems[1];
    rightItems[0].name = right_name;
    rightItems[0].value = "test";
    rightItems[0].valueLength = 5;

    AuthorizationRights rights = {
        .count = sizeof(rightItems) / sizeof(rightItems[0]),
        .items = rightItems,
    };

    AuthorizationItem envItems[1];
    envItems[0].name = kAuthorizationEnvironmentPrompt;
    envItems[0].value = prompt;
    envItems[0].valueLength = prompt_size;

    AuthorizationEnvironment env = {
        .count = sizeof(envItems) / sizeof(envItems[0]),
        .items = envItems,
    };

    code = AuthorizationCreate(
        &rights,
        &env,
        kAuthorizationFlagDefaults | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights,
        ref_ptr);

    free(right_name);
    free(prompt);

    if (code != errAuthorizationSuccess)
    {
        // ref_ptr is created for this function call,
        // and since the authorization failed,
        // it will never be used
        free(ref_ptr);
    }

    return code;
}

OSStatus destroy_auth(AuthorizationRef *ref_ptr)
{
    return AuthorizationFree(*ref_ptr, kAuthorizationFlagDestroyRights);
}
