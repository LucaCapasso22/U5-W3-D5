package user.1.u5w3d5.services;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Service;
import user.1.u5w3d5.entities.Evento;
import user.1.u5w3d5.entities.Prenotazione;
import user.1.u5w3d5.entities.Utente;
import user.1.u5w3d5.exceptions.NotFoundExceptions;
import user.1.u5w3d5.payloads.PrenotazioneDTO;
import user.1.u5w3d5.repositories.PrenotazioneDAO;

import java.time.LocalDate;
import java.util.List;

@Service
public class PrenotazioneService {
    @Autowired
    private PrenotazioneDAO prenotazioneDAO;
    @Autowired
    private UtenteService utenteService;
    @Autowired
    private EventoService eventoService;

    public List<Prenotazione> getPrenotazioni(){return this.prenotazioneDAO.findAll();}

    public Prenotazione savePrenotazione(PrenotazioneDTO body){
        Utente utente = utenteService.findById(body.utente_id());
        Evento evento = eventoService.findById(body.evento_id());
        Prenotazione prenotazione = new Prenotazione();
        prenotazione.setUtente(utente);
        prenotazione.setEvento(evento);
        prenotazione.setDataPrenotazione(LocalDate.now());
        prenotazione.setNumeroPartecipanti(body.numero_partecipanti());
        return prenotazioneDAO.save(prenotazione);
    }
    public Prenotazione findById(long id){
        return prenotazioneDAO.findById(id).orElseThrow(()->new NotFoundExceptions(id));
    }

    public Prenotazione findByIdAndUpdate(long id, PrenotazioneDTO body){
        Prenotazione found = this.findById(id);
        Utente utente = utenteService.findById(body.utente_id());
        Evento evento = eventoService.findById(body.evento_id());
        found.setDataPrenotazione(LocalDate.now());
        found.setEvento(evento);
        found.setUtente(utente);
        return prenotazioneDAO.save(found);
    }

    public void findByIdAndDelete(long id){
        Prenotazione found = this.findById(id);
        prenotazioneDAO.delete(found);
    }


}
