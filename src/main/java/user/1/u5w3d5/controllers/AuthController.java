package user.1.u5w3d5.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import user.1.u5w3d5.entities.Utente;
import user.1.u5w3d5.exceptions.BadRequestException;
import user.1.u5w3d5.payloads.UtenteDTO;
import user.1.u5w3d5.payloads.UtenteResponseDTO;
import user.1.u5w3d5.payloads.loginPayload.UtenteLoginDTO;
import user.1.u5w3d5.payloads.loginPayload.UtenteLoginResponseDTO;
import user.1.u5w3d5.services.AuthService;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;
    @PostMapping("/login")
    public UtenteLoginResponseDTO login(@RequestBody UtenteLoginDTO body){
        String accessToken = authService.authenticateUser(body);
        return new UtenteLoginResponseDTO(accessToken);
    }
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UtenteResponseDTO createUser(@RequestBody @Validated UtenteDTO newUserPayload, BindingResult validation) {
        if (validation.hasErrors()) {
            System.out.println(validation.getAllErrors());
            throw new BadRequestException(validation.getAllErrors());
        } else {
            Utente newUtente = authService.save(newUserPayload);
            return new UtenteResponseDTO(newUtente.getId());
        }
    }
}
