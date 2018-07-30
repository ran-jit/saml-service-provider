package service.provider.exception;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class UserAuthenticationException extends Exception {

    private static final long serialVersionUID = 8360417032000200780L;

    public UserAuthenticationException() {
        super("Unauthorized user.");
    }

}
