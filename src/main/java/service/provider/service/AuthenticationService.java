package service.provider.service;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import service.provider.exception.UserAuthenticationException;
import service.provider.model.SamlPrincipal;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
@Controller
@RequestMapping("/auth")
public class AuthenticationService {

    @GetMapping("/token")
    @CrossOrigin(origins = {"*"}, allowCredentials = "true")
    public ResponseEntity<SamlPrincipal> token() throws Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            SamlPrincipal principal = (SamlPrincipal) authentication.getPrincipal();
            return new ResponseEntity<>(principal, HttpStatus.OK);
        }
        throw new UserAuthenticationException();
    }

}
