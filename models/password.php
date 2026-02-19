<?php 
require_once __DIR__ . '/../config/ConfigLimites.php';

class Password
{
    private int    $length;
    private bool   $includeUppercase;
    private bool   $includeLowercase;
    private bool   $includeNumbers;
    private bool   $includeSymbols;
    private bool   $excludeAmbiguous;
    private string $customExclusions;

    private const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
    private const NUMBERS   = '0123456789';
    private const SYMBOLS   = '!@#$%^&*()-_=+[]{}|;:,.<>?';
    private const AMBIGUOUS = '0Ol1I';

    public function __construct(array $options = [])
    {
        $this->length           = $options['length']           ?? ConfigLimites::DEFAULT_LENGTH;
        $this->includeUppercase = $options['includeUppercase'] ?? true;
        $this->includeLowercase = $options['includeLowercase'] ?? true;
        $this->includeNumbers   = $options['includeNumbers']   ?? true;
        $this->includeSymbols   = $options['includeSymbols']   ?? false;
        $this->excludeAmbiguous = $options['excludeAmbiguous'] ?? false;
        $this->customExclusions = $options['exclude']          ?? '';
    }

    // ── Genera una contraseña ────────────────────────────────────────
    public function generate(): string
    {
        $charset = $this->buildCharset();

        if (strlen($charset) === 0) {
            throw new InvalidArgumentException(
                'El conjunto de caracteres está vacío. Activa al menos un tipo.'
            );
        }

        // Garantiza al menos 1 char de cada tipo habilitado
        $password = $this->buildRequired();

        // Rellena hasta la longitud deseada
        $maxIndex = strlen($charset) - 1;
        while (strlen($password) < $this->length) {
            $password .= $charset[random_int(0, $maxIndex)];
        }

        return $this->cryptoShuffle($password);
    }

    // ── Genera N contraseñas ─────────────────────────────────────────
    public function generateMany(int $count): array
    {
        $results = [];
        for ($i = 0; $i < $count; $i++) {
            $results[] = $this->generate();
        }
        return $results;
    }

    // ── Valida una contraseña contra requisitos ──────────────────────
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

    // ── Privados ─────────────────────────────────────────────────────
    private function buildCharset(): string
    {
        $charset = '';
        if ($this->includeUppercase) $charset .= self::UPPERCASE;
        if ($this->includeLowercase) $charset .= self::LOWERCASE;
        if ($this->includeNumbers)   $charset .= self::NUMBERS;
        if ($this->includeSymbols)   $charset .= self::SYMBOLS;

        if ($this->excludeAmbiguous) {
            $charset = str_replace(str_split(self::AMBIGUOUS), '', $charset);
        }
        if ($this->customExclusions !== '') {
            $charset = str_replace(str_split($this->customExclusions), '', $charset);
        }

        return $charset;
    }

    private function buildRequired(): string
    {
        $required = [];
        $pools    = [];

        if ($this->includeUppercase) $pools[] = self::UPPERCASE;
        if ($this->includeLowercase) $pools[] = self::LOWERCASE;
        if ($this->includeNumbers)   $pools[] = self::NUMBERS;
        if ($this->includeSymbols)   $pools[] = self::SYMBOLS;

        foreach ($pools as $pool) {
            if ($this->excludeAmbiguous) {
                $pool = str_replace(str_split(self::AMBIGUOUS), '', $pool);
            }
            if ($this->customExclusions !== '') {
                $pool = str_replace(str_split($this->customExclusions), '', $pool);
            }
            if (strlen($pool) > 0) {
                $required[] = $pool[random_int(0, strlen($pool) - 1)];
            }
        }

        return implode('', $required);
    }

    private function cryptoShuffle(string $str): string
    {
        $arr = str_split($str);
        for ($i = count($arr) - 1; $i > 0; $i--) {
            $j          = random_int(0, $i);
            [$arr[$i], $arr[$j]] = [$arr[$j], $arr[$i]];
        }
        return implode('', $arr);
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