package user.1.u5w3d5.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import user.1.u5w3d5.entities.Evento;
import user.1.u5w3d5.entities.Utente;

import java.util.Optional;

@Repository
public interface EventoDAO extends JpaRepository<Evento, Long> {
    Optional<Evento> findByTitolo(String titolo);
    Optional<Utente> findByLuogo(String luogo);


}
