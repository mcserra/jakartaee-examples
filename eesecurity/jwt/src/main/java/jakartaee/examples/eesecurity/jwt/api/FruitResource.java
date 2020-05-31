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
package jakartaee.examples.eesecurity.jwt.api;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.security.enterprise.SecurityContext;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

import static jakartaee.examples.eesecurity.jwt.security.Roles.*;

@Path("fruits")
public class FruitResource {

    @Inject
    private SecurityContext securityContext;

    @GET
    @Path("apple")
    @PermitAll
    public Response apple() {
        return Response.ok(securityContext.getCallerPrincipal()).build();
    }

    @GET
    @Path("cherry")
    @RolesAllowed({ROLE_USER, ROLE_ADMIN})
    public Response cherry() {
        return Response.ok(securityContext.getCallerPrincipal()).build();
    }

    @GET
    @Path("peach")
    @RolesAllowed({ROLE_ADMIN})
    public Response peach() {
        return Response.ok(securityContext.getCallerPrincipal()).build();
    }

    @GET
    @Path("pear")
    @DenyAll
    public Response none() {
        return Response.ok(securityContext.getCallerPrincipal()).build();
    }
}
