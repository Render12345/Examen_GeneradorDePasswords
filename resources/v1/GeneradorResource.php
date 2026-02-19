<?php

require_once __DIR__ . '/../../core/Respuesta.php';
require_once __DIR__ . '/../../models/password.php';
require_once __DIR__ . '/../../config/ConfigLimites.php';

class GeneradorResource
{
    // GET /v1/password ─────────────────────────────────────────────
    public function handleSingle(): void
    {
        $options = $this->extractOptions($_GET);
        $this->validateOptions($options);

        $model    = new Password($options);
        $password = $model->generate();

        Respuesta::success([
            'password' => $password,
            'length'   => strlen($password),
            'options'  => $options,
        ], 'Contraseña generada');
    }

    // POST /v1/passwords ───────────────────────────────────────────
    public function handleBatch(): void
    {
        $body  = $this->parseBody();
        $count = (int)($body['count'] ?? ConfigLimites::DEFAULT_COUNT);

        if ($count < 1 || $count > ConfigLimites::MAX_COUNT) {
            Respuesta::error(
                'count debe estar entre 1 y ' . ConfigLimites::MAX_COUNT, 400
            );
        }

        $options = $this->extractOptions($body);
        $this->validateOptions($options);

        $model     = new Password($options);
        $passwords = $model->generateMany($count);

        Respuesta::success([
            'passwords' => $passwords,
            'count'     => count($passwords),
            'options'   => $options,
        ], "{$count} contraseñas generadas");
    }

    // ── Helpers ───────────────────────────────────────────────────
    private function extractOptions(array $source): array
    {
        return [
            'length'           => (int)($source['length']           ?? ConfigLimites::DEFAULT_LENGTH),
            'includeUppercase' => $this->toBool($source['includeUppercase'] ?? true),
            'includeLowercase' => $this->toBool($source['includeLowercase'] ?? true),
            'includeNumbers'   => $this->toBool($source['includeNumbers']   ?? true),
            'includeSymbols'   => $this->toBool($source['includeSymbols']   ?? false),
            'excludeAmbiguous' => $this->toBool($source['excludeAmbiguous'] ?? false),
            'exclude'          => $source['exclude']                         ?? '',
        ];
    }

    private function validateOptions(array $options): void
    {
        $length = $options['length'];

        if ($length < ConfigLimites::MIN_LENGTH || $length > ConfigLimites::MAX_LENGTH) {
            Respuesta::error(
                'length debe estar entre ' . ConfigLimites::MIN_LENGTH .
                ' y ' . ConfigLimites::MAX_LENGTH . ' caracteres.', 400
            );
        }

        $anyEnabled = $options['includeUppercase']
                   || $options['includeLowercase']
                   || $options['includeNumbers']
                   || $options['includeSymbols'];

        if (!$anyEnabled) {
            Respuesta::error('Debes habilitar al menos un tipo de carácter.', 400);
        }
    }

    private function parseBody(): array
    {
        return json_decode(file_get_contents('php://input'), true) ?? [];
    }

    private function toBool(mixed $value): bool
    {
        if (is_bool($value)) return $value;
        return filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }
}
?>