<?php

require_once __DIR__ . '/../../core/Respuesta.php';
require_once __DIR__ . '/../../models/password.php';

class ValidadorResource
{
    public function handle(): void
    {
        $body = json_decode(file_get_contents('php://input'), true) ?? [];

        if (empty($body['password'])) {
            Respuesta::error('El campo "password" es requerido.', 400);
        }

        $requirements = $body['requirements'] ?? [];
        $result       = Password::validate($body['password'], $requirements);

        Respuesta::success(
            $result,
            $result['valid']
                ? 'Contraseña válida'
                : 'La contraseña no cumple los requisitos'
        );
    }
}
?>