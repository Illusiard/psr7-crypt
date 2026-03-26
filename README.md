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

## Ограничения текущей версии

- `EncryptedStream` и `DecryptedStream` являются read-only и не поддерживают `seek()`/`rewind()`
- `DecryptedStream` сначала валидирует весь encrypted payload, и только потом отдаёт plaintext
- `refKey` вычисляется как часть expanded key, но не используется

## Структура пакета

```text
src/
  Enum/
  Exception/
  Service/
  Stream/
  ValueObject/
tests/
  Unit/
  Integration/
```

## Разработка

Установка зависимостей:

```bash
composer install
```

Запуск тестов:

```bash
composer test
```
