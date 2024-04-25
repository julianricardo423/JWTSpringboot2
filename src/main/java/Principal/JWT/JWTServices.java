package Principal.JWT;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

@Service
public class JWTServices {

    private static final String SECRET_KEY = "6e49a80a2ee12dfc4d0cc6087e623c06df68fda5cb920850d11e797c5ddf0d3e";

    /*esta línea en particular llama a una sobrecarga del método getToken que toma dos argumentos: un mapa vacío y un objeto UserDetails. Esta sobrecarga específica del método getToken probablemente realiza alguna operación relacionada con la generación de un token de autenticación basado en el usuario proporcionado. La razón para pasar un mapa vacío como argumento adicional no está clara sin ver la implementación del método getToken. Es posible que el método getToken acepte opciones adicionales o configuraciones en forma de un mapa de llave-valor, y en este caso, se está usando un mapa vacío como valor predeterminado*/
    public String getToken(UserDetails user) {
        return getToken(new HashMap<String, Object>(), user);
    }

    /*esta línea de código genera un token JWT con las reclamaciones proporcionadas, incluyendo el nombre de usuario como sujeto, y firma el token utilizando una clave específica y el algoritmo HS256.*/
    private String getToken(HashMap<String, Object> extraClaims, UserDetails user) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /*este método getKey decodifica una cadena Base64 que contiene la clave secreta y luego crea una instancia de una clave HMAC-SHA utilizando estos bytes decodificados. Esta clave se utiliza para firmar los tokens JWT en el método getToken*/
    private Key getKey() {
        /*Decodificamos nuestra sectret key*/
        byte[] keBytes= Decoders.BASE64.decode(SECRET_KEY);

        /*Nos permite crear una nueva instancia de nuestra secret key*/
        return Keys.hmacShaKeyFor(keBytes);
    }

    /*Obtiene el usuario al que pertenece el token
    * esta línea de código llama a un método que obtiene el nombre de usuario (sujeto) del token JWT proporcionado. La llamada se realiza a través de una referencia a un método de la clase Claims, que es una parte integral de la manipulación de tokens JWT*/
    public String getUserNameFromToken(String token) {
        return getClaim(token, Claims::getSubject);//Método de referencia Claims::getSubject
    }

    /*esta línea de código verifica si un token JWT dado es válido para el usuario proporcionado. Primero, comprueba si el nombre de usuario del token coincide con el nombre de usuario del objeto UserDetails proporcionado, y luego verifica si el token no ha expirado. Si ambas condiciones son verdaderas, el método devuelve true, indicando que el token es válido; de lo contrario, devuelve false*/
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName = getUserNameFromToken(token);
        return userName.equals(userDetails.getUsername())&& !isTokenExpired(token);
    }

    /*esta línea de código analiza un token JWT, verifica su firma utilizando una clave de firma especificada y devuelve todas las reclamaciones contenidas en el token.*/
    private Claims getAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /*toma el objeto claims que contiene los reclamos del token JWT y aplica la función claimsResolver a ese objeto. La función claimsResolver se proporciona como argumento al método getClaim y se espera que extraiga un reclamo específico del tipo T del objeto claims. Finalmente, el reclamo extraído se devuelve como resultado del método getClaim. En resumen, esta línea de código devuelve un reclamo específico del token JWT*/
    public <T> T getClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /*Obtiene la fecha de expiración del token*/
    private Date getExpiration(String token){
        return getClaim(token, Claims::getExpiration);
    }

    /*Verifica si el token supero el tiempo de expiración de acuerdo a la hora del sistema*/
    private boolean isTokenExpired(String token){
        return getExpiration(token).before(new Date());
    }
}
