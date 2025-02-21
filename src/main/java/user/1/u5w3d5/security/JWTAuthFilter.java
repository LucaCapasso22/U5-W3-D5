package user.1.u5w3d5.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import user.1.u5w3d5.entities.Utente;
import user.1.u5w3d5.exceptions.UnauthorizedException;
import user.1.u5w3d5.services.UtenteService;

import java.io.IOException;
import java.util.stream.Stream;

@Component
public class JWTAuthFilter extends OncePerRequestFilter {
    private static final AntPathMatcher pathMatcher = new AntPathMatcher();
    @Autowired
    private JWTtools jwTtools;
    @Autowired
    private UtenteService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new UnauthorizedException("Per favore metti il token nell'Authorization header");
        } else {
            String accessToken = authHeader.substring(7);
            jwTtools.verifyToken(accessToken);

            String id = jwTtools.extractIdFromToken(accessToken);
            Utente user = userService.findById(Long.parseLong(id));

            Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);


            filterChain.doFilter(request, response);

    }
}
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String[] allowedPaths = {"/auth/**", "/swagger-ui/**", "/v3/**"};

        return Stream.of(allowedPaths)
                .anyMatch(path -> pathMatcher.match(path, request.getServletPath()));
    }
    //    @Override
//    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
//        return new AntPathMatcher().match("/auth/**", request.getServletPath());
//    }

}

////        http://localhost:3001/v3/api-docs.yaml
////        http://localhost:3001/swagger-ui/index.html
