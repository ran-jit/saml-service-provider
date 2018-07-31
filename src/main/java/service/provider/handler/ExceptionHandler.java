package service.provider.handler;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ResponseStatus;
import service.provider.exception.UserAuthenticationException;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
@ControllerAdvice
public class ExceptionHandler {

    @Getter
    @Setter
    @Builder
    @ToString
    @NoArgsConstructor
    @AllArgsConstructor
    private static class Error implements Serializable {

        private static final long serialVersionUID = 5754254366408374446L;

        private Boolean status;

        private HttpStatus httpStatus;

        @JsonFormat(shape = JsonFormat.Shape.STRING)
        private LocalDateTime timestamp;

        private String message;
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @org.springframework.web.bind.annotation.ExceptionHandler(value = UserAuthenticationException.class)
    public Error handleBaseException() {
        return error(HttpStatus.UNAUTHORIZED, null);
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @org.springframework.web.bind.annotation.ExceptionHandler(value = Exception.class)
    public Error handleException(Exception ex) {
        return error(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
    }

    private Error error(HttpStatus status, String message) {
        return Error.builder()
                .httpStatus(status)
                .message(message)
                .status(Boolean.FALSE)
                .timestamp(LocalDateTime.now())
                .build();
    }

}
