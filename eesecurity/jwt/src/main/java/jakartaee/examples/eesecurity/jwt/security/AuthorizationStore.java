/*
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package jakartaee.examples.eesecurity.jwt.security;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;

import static java.util.Arrays.asList;
import static java.util.Collections.singleton;
import static javax.security.enterprise.identitystore.IdentityStore.ValidationType.PROVIDE_GROUPS;

@RequestScoped
public class AuthorizationStore implements IdentityStore {

    private final Map<String, Set<String>> userGroups = new HashMap<>();

    @PostConstruct
    public void init() {
        userGroups.put(Roles.USER_FOO, new HashSet<>(asList(Roles.ROLE_USER, Roles.ROLE_ADMIN)));
        userGroups.put(Roles.USER_BAR, singleton(Roles.ROLE_USER));
    }

    @Override
    public Set<String> getCallerGroups(final CredentialValidationResult validationResult) {
        final Set<String> result = userGroups.get(validationResult.getCallerPrincipal().getName());
        return result == null ? Collections.emptySet() : result;
    }

    @Override
    public Set<ValidationType> validationTypes() {
        return Collections.singleton(PROVIDE_GROUPS);
    }

}
