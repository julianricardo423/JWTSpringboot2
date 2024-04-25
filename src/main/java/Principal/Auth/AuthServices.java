package Principal.Auth;

import Principal.Entity.Rol;
import Principal.Entity.User;
import Principal.JWT.JWTServices;
import Principal.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServices {

    private final UserRepository repository;
    private final JWTServices jwtServices;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    /*esta línea de código representa el proceso de autenticación de un usuario, la generación de un token JWT después de la autenticación exitosa y la creación de un objeto AuthResponse que contiene el token JWT*/
    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUserName(), request.getPassword()));
        UserDetails user = repository.findByUserName(request.getUserName()).orElseThrow();
        String token = jwtServices.getToken(user);
        return AuthResponse.builder().token(token).build();
    }

    /*esta línea de código representa el proceso de registro de un nuevo usuario, donde se crea un nuevo objeto User, se guarda en la base de datos y se genera un token JWT para el usuario registrado, que luego se devuelve como parte de una respuesta AuthResponse*/
    public AuthResponse register(RegisterRequest request) {
        User user = User.builder().
                userName(request.getUserName())
                .lastName(request.getLastName())
                .firstName(request.getFirstName())
                .password(passwordEncoder.encode(request.getPassword()))
                .country(request.getCountry())
                .rol(Rol.USER).build();

        repository.save(user);

        /*Aquí devuelve la respuesta AuthResponse, pero obteniendo el token de la entidad user*/
        return AuthResponse.builder()
                .token(jwtServices.getToken(user))
                .build();
    }
}
