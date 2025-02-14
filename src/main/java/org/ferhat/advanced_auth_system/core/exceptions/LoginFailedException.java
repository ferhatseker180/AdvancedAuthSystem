package org.ferhat.advanced_auth_system.core.exceptions;


import org.ferhat.advanced_auth_system.core.utils.ApiMessage;
import org.springframework.http.HttpStatus;

public class LoginFailedException extends BaseException{

    public LoginFailedException() {
        super(ApiMessage.LOGIN_FAILED, HttpStatus.UNAUTHORIZED);
    }
}
