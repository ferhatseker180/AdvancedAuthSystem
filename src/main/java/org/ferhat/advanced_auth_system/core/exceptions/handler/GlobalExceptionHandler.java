package org.ferhat.advanced_auth_system.core.exceptions.handler;

import org.ferhat.advanced_auth_system.core.exceptions.BaseException;
import org.ferhat.advanced_auth_system.core.utils.ApiMessage;
import org.ferhat.advanced_auth_system.dto.response.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(BaseException.class)
    public ResponseEntity<ApiResponse<?>> handleBaseException(BaseException ex) {
        return ResponseEntity
                .status(ex.getHttpStatus())
                .body(ApiResponse.error(ex.getApiMessage(), ex.getHttpStatus().value()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<?>> handleGeneralException(Exception ex) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error(ApiMessage.VALIDATION_ERROR, HttpStatus.INTERNAL_SERVER_ERROR.value()));
    }
}
