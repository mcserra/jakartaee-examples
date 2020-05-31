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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStoreHandler;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;

@RequestScoped
public class AuthenticationMechanism implements HttpAuthenticationMechanism {

    private static final String SECRET_KEY = "SECRET_KEY";
    private static final String BEARER = "Bearer ";

    @Inject
    private IdentityStoreHandler identityStore;

    @Override
    public AuthenticationStatus validateRequest(
        final HttpServletRequest request,
        final HttpServletResponse response,
        final HttpMessageContext context
    ) {
        AuthenticationStatus status = context.doNothing();
        final String user = extractHeader(context, "user");
        final String password = extractHeader(context, "password");
        final Optional<String> token = extractRequestToken(context);

        if (user != null && password != null) {
            CredentialValidationResult validationResult = identityStore.validate(new UsernamePasswordCredential(user, password));
            if (CredentialValidationResult.Status.VALID == validationResult.getStatus()) {
                addTokenToHeader(validationResult, context);
                status = context.notifyContainerAboutLogin(validationResult.getCallerPrincipal(), validationResult.getCallerGroups());
            } else {
                status = context.responseUnauthorized();
            }
        } else if (token.isPresent()) {
            if (isValidToken(token.get())) {
                JWTCredential credential = credential(token.get());
                status = context.notifyContainerAboutLogin(credential.callerName, credential.groups);
            } else {
                status = context.responseUnauthorized();
            }
        } else if (context.isProtected()) {
            status = context.responseUnauthorized();
        }
        return status;
    }

    private void addTokenToHeader(final CredentialValidationResult validationResult, final HttpMessageContext context) {
        String jwt = jwt(validationResult.getCallerPrincipal().getName(), validationResult.getCallerGroups());
        context.getResponse().setHeader(HttpHeaders.AUTHORIZATION, BEARER + jwt);
    }

    private Optional<String> extractRequestToken(final HttpMessageContext context) {
        String authorizationHeader = context.getRequest().getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER)) {
            return Optional.of(authorizationHeader.substring(BEARER.length()));
        }
        return Optional.empty();
    }

    private String extractHeader(final HttpMessageContext context, final String header) {
        return context.getRequest().getHeader(header);
    }

    private boolean isValidToken(final String authToken) {
        try {
            Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            return false;
        }
    }

    private JWTCredential credential(final String token) {
        Claims claims = Jwts.parser()
            .setSigningKey(SECRET_KEY)
            .parseClaimsJws(token)
            .getBody();

        Set<String> groups = new HashSet<>(Arrays.asList(claims.get("auth").toString().split(",")));

        return new JWTCredential(claims.getSubject(), groups);
    }

    private String jwt(final String username, final Set<String> authorities) {
        Instant instant = Instant.now().plus(1, ChronoUnit.DAYS);
        return Jwts.builder()
            .setSubject(username)
            .claim("auth", String.join(",", authorities))
            .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
            .setExpiration(Date.from(instant))
            .compact();
    }

    private static class JWTCredential {
        private final String callerName;
        private final Set<String> groups;

        public JWTCredential(final String callerName, final Set<String> groups) {
            this.callerName = callerName;
            this.groups = groups;
        }
    }
}
