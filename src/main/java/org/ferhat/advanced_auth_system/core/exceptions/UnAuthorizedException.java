package org.ferhat.advanced_auth_system.core.exceptions;

import org.ferhat.advanced_auth_system.core.utils.ApiMessage;
import org.springframework.http.HttpStatus;

public class UnAuthorizedException extends BaseException {
    public UnAuthorizedException() {
        super(ApiMessage.UNAUTHORIZED, HttpStatus.UNAUTHORIZED);
    }
}
