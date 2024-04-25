package Principal.Config;

import Principal.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository repository;
    /*Acceder al manejador de las instancias en este caso AuthenticationManager*/
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception{
        return config.getAuthenticationManager();
    }

    /*Devuelve el provedor
    * En resumen, este método configura un proveedor de autenticación personalizado utilizando un UserDetailsService y un PasswordEncoder, que son componentes clave en la autenticación de usuarios en una aplicación web segura con Spring Security*/

    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();

        authenticationProvider.setUserDetailsService(userDetailService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());

        return authenticationProvider;
    }

    /*Cuando un usuario crea una contraseña nueva (por ejemplo, durante el proceso de registro), esta contraseña se pasa a través del BCryptPasswordEncoder, que la codifica utilizando un algoritmo de hashing seguro (bcrypt). Luego, esta contraseña hash se almacena en la base de datos. Cuando un usuario intenta iniciar sesión, la contraseña proporcionada se vuelve a codificar utilizando el mismo algoritmo y se compara con la versión almacenada en la base de datos para verificar la autenticidad*/
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*En este caso, el método usa una expresión lambda para implementar la interfaz UserDetailsService. La expresión lambda toma un nombre de usuario como entrada y luego busca ese nombre de usuario en algún repositorio (probablemente una base de datos) utilizando un método llamado findByUserName() en un objeto repository. Si encuentra un usuario con ese nombre, devuelve sus detalles. Si no lo encuentra, lanza una excepción UsernameNotFoundException
    * esta línea de código crea un bean de UserDetailsService que utiliza un repositorio para cargar los detalles del usuario a partir de su nombre de usuario, y lanza una excepción si el usuario no es encontrado en el repositorio. Esto se utiliza típicamente en la configuración de seguridad de Spring para cargar los detalles de usuario durante el proceso de autenticación*/

    @Bean
    public UserDetailsService userDetailService() {
        return userName -> repository.findByUserName(userName)
                .orElseThrow(() -> new UsernameNotFoundException("User not found" + userName));
    }
}
