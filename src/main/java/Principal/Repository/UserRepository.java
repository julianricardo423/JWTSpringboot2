package Principal.Repository;

import Principal.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    //Al ser opcional puede devolver un nulo si así es
    Optional<User> findByUserName(String userName);
}
