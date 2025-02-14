package org.ferhat.advanced_auth_system.core.exceptions;

import org.ferhat.advanced_auth_system.core.utils.ApiMessage;
import org.springframework.http.HttpStatus;

public class BaseException extends RuntimeException {
    private final ApiMessage apiMessage;
    private final HttpStatus httpStatus;

    public BaseException(ApiMessage apiMessage, HttpStatus httpStatus) {
        this.apiMessage = apiMessage;
        this.httpStatus = httpStatus;
    }

    public ApiMessage getApiMessage() {
        return apiMessage;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
