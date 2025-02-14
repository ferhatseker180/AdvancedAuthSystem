package org.ferhat.advanced_auth_system.core.exceptions;

import org.ferhat.advanced_auth_system.core.utils.ApiMessage;
import org.springframework.http.HttpStatus;

public class ValidationException extends BaseException{
    public ValidationException() {
        super(ApiMessage.VALIDATION_ERROR, HttpStatus.BAD_REQUEST);
    }
}
