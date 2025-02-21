package user.1.u5w3d5.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import user.1.u5w3d5.entities.Utente;

import java.util.Optional;

@Repository
public interface UtenteDAO extends JpaRepository <Utente, Long>{
    Optional<Utente> findByEmail(String email);
    Optional<Utente> findByUsername(String username);

}
