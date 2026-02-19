<?php

class Respuesta
{
    public static function success(mixed $data, string $message = 'OK', int $code = 200): void
    {
        self::json([
            'success' => true,
            'message' => $message,
            'data'    => $data,
        ], $code);
    }

    public static function error(string $message, int $code = 400, array $extra = []): void
    {
        self::json(array_merge([
            'error'   => true,
            'code'    => $code,
            'message' => $message,
        ], $extra), $code);
    }

    private static function json(mixed $data, int $code): void
    {
        http_response_code($code);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }
}
?>