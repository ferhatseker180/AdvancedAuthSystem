package org.ferhat.advanced_auth_system.core.exceptions;

import org.ferhat.advanced_auth_system.core.utils.ApiMessage;
import org.springframework.http.HttpStatus;

public class UserNotFoundException extends BaseException{
    public UserNotFoundException() {
        super(ApiMessage.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
    }
}
