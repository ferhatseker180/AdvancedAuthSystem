package org.ferhat.advanced_auth_system.dto.response;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.ferhat.advanced_auth_system.core.utils.ApiMessage;

@NoArgsConstructor
public class ApiResponse<T> {
    private boolean success;
    private String message;
    private int statusCode;
    private T data;

    public ApiResponse(boolean success, String message, int statusCode, T data) {
        this.success = success;
        this.message = message;
        this.statusCode = statusCode;
        this.data = data;
    }

    public static <T> ApiResponse<T> success(T data, int statusCode, ApiMessage message) {
        return new ApiResponse<>(true, message.getMessage(), statusCode, data);
    }

    public static <T> ApiResponse<T> error(ApiMessage message, int statusCode) {
        return new ApiResponse<>(false, message.getMessage(), statusCode, null);
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }
}

