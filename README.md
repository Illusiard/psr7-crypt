# Illusiard PSR-7 Crypt

`illusiard/psr7-crypt` это библиотека для PHP 8.5, предназначенная для шифрования и дешифрования PSR-7 потоков в формате WhatsApp media encryption.

## Возможности

- расширение 32-байтного `mediaKey` в WhatsApp-compatible key material через HKDF SHA-256
- потоковое шифрование PSR-7 потоков через AES-256-CBC
- потоковое дешифрование PSR-7 потоков с обязательной проверкой truncated MAC
- генерация `sidecar` для streamable media без повторного чтения исходного plaintext-потока
- поддержка sample-векторов для `IMAGE`, `AUDIO`, `VIDEO`

## Требования

- PHP 8.5+
- `psr/http-message`
- `guzzlehttp/psr7`

## Установка

```bash
composer require illusiard/psr7-crypt
```

## Основные сущности

- `MediaType` определяет application info для HKDF и знает, поддерживает ли тип sidecar
- `MediaKey` и `ExpandedMediaKey` инкапсулируют ключевой материал
- `KeyExpander` расширяет `mediaKey` в `iv`, `cipherKey`, `macKey`, `refKey`
- `EncryptedStream` шифрует plaintext-поток в ciphertext + truncated MAC
- `DecryptedStream` валидирует MAC и отдаёт расшифрованный plaintext
- `Sidecar` представляет готовые sidecar-данные для streamable media

## Поддерживаемые media types

- `MediaType::Image`
- `MediaType::Video`
- `MediaType::Audio`
- `MediaType::Document`

Для `Video` и `Audio` можно генерировать sidecar.

Формула sidecar в библиотеке выражена явно:

- sidecar строится по входной последовательности `IV + ciphertext + final truncated MAC`
- последовательность режется окнами вида `[n*64K, (n+1)*64K+16]`
- для каждого окна считается `HMAC-SHA256`, после чего берутся первые 10 байт
- итоговый `Sidecar` это конкатенация всех таких 10-байтных подписей

## Пример шифрования

```php
<?php

use GuzzleHttp\Psr7\Utils;
use Illusiard\Psr7Crypt\Enum\MediaType;
use Illusiard\Psr7Crypt\Service\KeyExpander;
use Illusiard\Psr7Crypt\Stream\EncryptedStream;
use Illusiard\Psr7Crypt\ValueObject\MediaKey;

$mediaKey = new MediaKey(random_bytes(32));
$expandedMediaKey = (new KeyExpander())->expand($mediaKey, MediaType::Image);

$sourceStream = Utils::streamFor(fopen('/path/to/plain.bin', 'rb'));
$encryptedStream = new EncryptedStream($sourceStream, $expandedMediaKey);

$encryptedPayload = $encryptedStream->getContents();
```

## Пример дешифрования

```php
<?php

use GuzzleHttp\Psr7\Utils;
use Illusiard\Psr7Crypt\Enum\MediaType;
use Illusiard\Psr7Crypt\Service\KeyExpander;
use Illusiard\Psr7Crypt\Stream\DecryptedStream;
use Illusiard\Psr7Crypt\ValueObject\MediaKey;

$mediaKey = new MediaKey(file_get_contents('/path/to/media.key'));
$expandedMediaKey = (new KeyExpander())->expand($mediaKey, MediaType::Video);

$encryptedStream = Utils::streamFor(fopen('/path/to/media.encrypted', 'rb'));
$decryptedStream = new DecryptedStream($encryptedStream, $expandedMediaKey);

$plaintext = $decryptedStream->getContents();
```

## Пример sidecar

```php
<?php

use GuzzleHttp\Psr7\Utils;
use Illusiard\Psr7Crypt\Enum\MediaType;
use Illusiard\Psr7Crypt\Service\KeyExpander;
use Illusiard\Psr7Crypt\Stream\EncryptedStream;
use Illusiard\Psr7Crypt\ValueObject\MediaKey;

$mediaKey = new MediaKey(file_get_contents('/path/to/media.key'));
$expandedMediaKey = (new KeyExpander())->expand($mediaKey, MediaType::Audio);

$sourceStream = Utils::streamFor(fopen('/path/to/audio.original', 'rb'));
$encryptedStream = new EncryptedStream(
    $sourceStream,
    $expandedMediaKey,
    MediaType::Audio->supportsSidecar()
);

$encryptedPayload = $encryptedStream->getContents();

if ($encryptedStream->hasSidecar() && $encryptedStream->isSidecarReady()) {
    $sidecar = $encryptedStream->getSidecar();
    $sidecarBytes = $sidecar->getValue();
}
```

Внутри sidecar-цепочка собирается явно из трёх частей:

- initialization vector
- ciphertext
- final truncated MAC

Это важно для совместимости с sample sidecar и для предсказуемого поведения API.

## Ограничения текущей версии

- `EncryptedStream` и `DecryptedStream` являются read-only и не поддерживают `seek()`/`rewind()`
- `DecryptedStream` работает потоково, но удерживает последний block и хвост `MAC` до финальной проверки целостности
- `refKey` вычисляется как часть expanded key, но не используется

## Структура пакета

```text
task/
  samples/
src/
  Enum/
  Exception/
  Service/
  Stream/
  ValueObject/
tests/
  Unit/
  Integration/
  Samples/
```

## Sample-файлы

Для проверки библиотеки используются sample-файлы из папки `task/samples`.

Ожидаемые типы файлов:

- `*.original`
- `*.encrypted`
- `*.key`
- `*.sidecar`

Если добавляются новые sample-сценарии, их нужно класть именно в `task/samples`, чтобы они могли использоваться в автоматических тестах без хардкода содержимого в коде.

## Разработка

Установка зависимостей:

```bash
composer install
```

Запуск тестов:

```bash
composer test
```

Отдельно в набор входят sample-тесты из `tests/Samples`, которые:

- читают sample-файлы напрямую из файловой системы
- побайтно проверяют encrypt/decrypt roundtrip against fixtures
- проверяют sidecar для доступных streamable sample-файлов
- прогоняют сценарии полного и частичного чтения
- покрывают негативные случаи с повреждённым ciphertext и MAC
