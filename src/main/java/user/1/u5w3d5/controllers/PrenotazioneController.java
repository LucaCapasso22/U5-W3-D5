package user.1.u5w3d5.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import user.1.u5w3d5.entities.Prenotazione;
import user.1.u5w3d5.entities.Utente;
import user.1.u5w3d5.payloads.PrenotazioneDTO;
import user.1.u5w3d5.payloads.PrenotazioneResponseDTO;
import user.1.u5w3d5.services.PrenotazioneService;

import java.util.List;

@RestController
@RequestMapping("/prenotazioni")
public class PrenotazioneController {
    @Autowired
    private PrenotazioneService prenotazioneService;
    @GetMapping
    @PreAuthorize("hasAuthority('ADMIN')")
    public List<Prenotazione> getPrenotazioni(){return this.prenotazioneService.getPrenotazioni();}
    @PostMapping
    @PreAuthorize("hasAuthority('ADMIN')")
    public PrenotazioneResponseDTO savePrenotazioni(@RequestBody PrenotazioneDTO payload){
        Prenotazione a = prenotazioneService.savePrenotazione(payload);
        return new PrenotazioneResponseDTO(a.getId());
    }
}
