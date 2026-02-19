<?php

require_once __DIR__ . '/../config/ConfigLimites.php';
require_once __DIR__ . '/GenPassword.php';

class Password
{
    private int   $length;
    private array $opts;

    public function __construct(array $options = [])
    {
        $this->length = $options['length'] ?? ConfigLimites::DEFAULT_LENGTH;

        // Traduce parámetros de la API → formato de GenPassword.php
        $this->opts = [
            'upper'           => $options['includeUppercase'] ?? true,
            'lower'           => $options['includeLowercase'] ?? true,
            'digits'          => $options['includeNumbers']   ?? true,
            'symbols'         => $options['includeSymbols']   ?? false,
            'avoid_ambiguous' => $options['excludeAmbiguous'] ?? false,
            'exclude'         => $options['exclude']          ?? '',
            'require_each'    => true,
        ];
    }

    // ── Una contraseña ───────────────────────────────────────────────
    public function generate(): string
    {
        return generate_password($this->length, $this->opts);
    }

    // ── Múltiples contraseñas ────────────────────────────────────────
    public function generateMany(int $count): array
    {
        return generate_passwords($count, $this->length, $this->opts);
    }

    // ── Validación + análisis de fortaleza ───────────────────────────
    public static function validate(string $password, array $requirements): array
    {
        $minLength        = $requirements['minLength']        ?? 8;
        $requireUppercase = $requirements['requireUppercase'] ?? false;
        $requireLowercase = $requirements['requireLowercase'] ?? false;
        $requireNumbers   = $requirements['requireNumbers']   ?? false;
        $requireSymbols   = $requirements['requireSymbols']   ?? false;

        $checks = [
            'length'    => strlen($password) >= $minLength,
            'uppercase' => !$requireUppercase || (bool)preg_match('/[A-Z]/', $password),
            'lowercase' => !$requireLowercase || (bool)preg_match('/[a-z]/', $password),
            'numbers'   => !$requireNumbers   || (bool)preg_match('/[0-9]/', $password),
            'symbols'   => !$requireSymbols   || (bool)preg_match('/[^a-zA-Z0-9]/', $password),
        ];

        $entropy  = self::calcEntropy($password);
        $strength = self::calcStrength($entropy);

        return [
            'valid'    => !in_array(false, $checks, true),
            'checks'   => $checks,
            'entropy'  => round($entropy, 2),
            'strength' => $strength,
        ];
    }

    private static function calcEntropy(string $password): float
    {
        $poolSize = 0;
        if (preg_match('/[a-z]/', $password)) $poolSize += 26;
        if (preg_match('/[A-Z]/', $password)) $poolSize += 26;
        if (preg_match('/[0-9]/', $password)) $poolSize += 10;
        if (preg_match('/[^a-zA-Z0-9]/', $password)) $poolSize += 32;

        return $poolSize > 0 ? strlen($password) * log($poolSize, 2) : 0;
    }

    private static function calcStrength(float $entropy): string
    {
        if ($entropy < 28)  return 'muy débil';
        if ($entropy < 36)  return 'débil';
        if ($entropy < 60)  return 'moderada';
        if ($entropy < 128) return 'fuerte';
        return 'muy fuerte';
    }
}
?>