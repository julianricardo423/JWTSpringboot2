package Principal.JWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
/*Se hereda de la clase abstracta OncePerRequestFilter, para que se pueda realizar filtros personalizados, garantiza que el filtro se ejecute solo una vez por cada solicitud http realiza, incluso si hay multiple filtros dentro de la cadena de filtros*/
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final JWTServices jwtServices;
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //Vamos a obtener el token del request
        final String token = getTokenFromRequest(request);
        final String userName;

        //En caso que el token sea nulo, devolvemos a filter chain el request y el response y lo retornamos
        if(token == null){
            filterChain.doFilter(request, response);
            return;
        }

        //En caso que no sea nulo, va a obtener el nombre de usuario por medio del token
        userName = jwtServices.getUserNameFromToken(token);

        /*En caso que el usuario sea diferente de null y actualmente no se encuentre logeado
        * Esta parte del código se encarga de la autenticación del usuario
        * esta parte del código se encarga de autenticar a un usuario utilizando un token JWT válido y establecer la autenticación en el contexto de seguridad de Spring. Esto es común en aplicaciones web seguras que utilizan Spring Security para la gestión de la autenticación y la autorización*/

        if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

            if(jwtServices.isTokenValid(token, userDetails)){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }

    /*Método para obtener el token del request
    * este método se utiliza para extraer un token de autorización de una solicitud HTTP que utiliza el esquema "Bearer"*/
    private String getTokenFromRequest(HttpServletRequest request) {
        //Obtener el encabezado, o sea, HS256
        final String autHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(StringUtils.hasText(autHeader) && autHeader.startsWith("Bearer ")){
            /*Apartir del caracter 7 hasta el final es el token*/
            return autHeader.substring(7);
        }
        /*En caso de no cumplir con la condición devuelva null*/
        return null;
    }
}
