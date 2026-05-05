# 🛡 VLESS Aggregator & Checker

Десктопное приложение на Python (customtkinter) для **автоматического сбора и
проверки VLESS-прокси**. Тёмная тема, табличный интерфейс, многопоточная проверка
через локальный [Xray-core](https://github.com/XTLS/Xray-core), фильтр «только IPv6»,
импорт из подписок / Telegram / буфера обмена / файла, экспорт рабочих ссылок.

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey) [![Build](https://github.com/Lorenovv/VLESS-Aggregator-Checker/actions/workflows/build.yml/badge.svg)](https://github.com/Lorenovv/VLESS-Aggregator-Checker/actions/workflows/build.yml)

## Возможности

- **Скрапинг** VLESS-ссылок из публичных подписок (V2rayCollector, TVC и т. п.) —
  встроенный список можно дополнять в настройках.
- **Telegram-скрапинг** (опционально, через Telethon): подключение к указанным
  каналам + поиск новых каналов по ключевым словам.
- **Ручной импорт**: текст из буфера обмена, файл `.txt`/`.list`/`.cfg`.
- **Фильтр «только IPv6»** — резолвит AAAA-записи через `dnspython`.
- **Многопоточная проверка** через локальный Xray-core: для каждой ссылки
  поднимается временный конфиг с SOCKS5-инбаундом, выполняется HTTP-запрос на
  `cp.cloudflare.com` или `gstatic.com/generate_204`, измеряется пинг и статус.
- **Управление**: «Обновить», «Проверить всё», «Стоп», «Очистить», поиск,
  фильтры (Все / Рабочие / Нерабочие).
- **Экспорт**: «Копировать рабочие в буфер», «Сохранить рабочие в файл».
- **Автообновление по расписанию** (раз в N минут).
- **Кроссплатформенно**: Windows, macOS, Linux. Всё в одном файле `app.py`.

## Установка

### 🪟 Windows: готовый .exe (без установки Python)

Самый простой вариант — скачать собранный `VLESS-Aggregator-Checker.exe`:

1. Перейдите на страницу [Actions](https://github.com/Lorenovv/VLESS-Aggregator-Checker/actions/workflows/build.yml).
2. Откройте последний успешный запуск (✅) → секция **Artifacts** →
   **VLESS-Aggregator-Checker-windows-exe** → скачайте архив.
3. Распакуйте и запустите `VLESS-Aggregator-Checker.exe`.

Стабильные сборки также публикуются на странице
[Releases](https://github.com/Lorenovv/VLESS-Aggregator-Checker/releases) при
выпуске тега `vX.Y.Z`.

> Windows SmartScreen может предупредить о неподписанном исполняемом файле — это
> нормально для бинарников из CI без code-signing сертификата. Нажмите
> «Подробнее» → «Выполнить в любом случае».

### 🐍 Запуск из исходников (любая ОС)

Требуется **Python 3.10+** и **Tk** (на Linux может потребоваться установить
`python3-tk` через пакетный менеджер).

```bash
git clone https://github.com/Lorenovv/VLESS-Aggregator-Checker.git
cd VLESS-Aggregator-Checker

# (рекомендуется) виртуальное окружение
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

pip install -r requirements.txt
```

### Установка Xray-core

Приложение использует **внешний** бинарник Xray для проверки прокси. Скачайте
релиз для своей ОС с https://github.com/XTLS/Xray-core/releases и распакуйте
куда удобно. Путь к бинарнику задаётся в настройках приложения (⚙ Настройки
→ «Путь к Xray») или ищется автоматически в `PATH`.

## Запуск

```bash
python app.py
```

При первом запуске рядом с `app.py` создадутся файлы конфигурации:

- `settings.json` — настройки (путь к Xray, потоки, таймаут, Telegram, …).
- `sources.json` — список URL-источников подписок.
- `temp_xray_configs/` — временные конфиги Xray (создаются и удаляются на лету).

## Как пользоваться

1. Нажмите **🔄 Обновить из источников** — приложение скачает и распарсит все
   подписки, удалит дубликаты и заполнит таблицу.
2. (опционально) Включите **«Только IPv6»** — на этапе сбора будут оставлены
   только хосты с IPv6.
3. Нажмите **✅ Проверить всё** — Xray запустится для каждой ссылки в
   отдельном потоке, измерит пинг и проставит статус (🟢 / 🔴).
4. Используйте фильтры и поиск, скопируйте или сохраните рабочие прокси
   кнопками **📋 Копировать рабочие** / **💾 Сохранить рабочие**.

### Telegram-скрапинг (опционально)

1. Получите `api_id` и `api_hash` на https://my.telegram.org → API development
   tools.
2. Откройте **⚙ Настройки → Telegram**, включите опцию, введите ключи и список
   каналов / поисковых слов.
3. При первом подключении Telethon запросит код подтверждения **в консоли**
   (`stdout/stdin`), поэтому запускайте `python app.py` из терминала.

## Структура проекта

```
.
├── app.py                              # вся логика и UI (один файл)
├── requirements.txt                    # зависимости
├── .github/workflows/build.yml         # автосборка Windows .exe (PyInstaller)
├── README.md
├── LICENSE
└── .gitignore
```

## Сборка .exe вручную (если нужно локально)

```bash
pip install pyinstaller
pyinstaller --onefile --windowed \
    --name "VLESS-Aggregator-Checker" \
    --collect-all customtkinter \
    --hidden-import dns.resolver \
    --hidden-import telethon \
    app.py
# Готовый бинарник: dist/VLESS-Aggregator-Checker.exe
```

То же самое автоматически делает GitHub Actions при push в `main` или
открытии PR — артефакт лежит на странице Actions, релиз создаётся при
тегировании.

## Лицензия

MIT — см. файл `LICENSE`. Используйте на свой страх и риск; приложение
получает прокси-ссылки из открытых источников, автор не несёт ответственности
за их работоспособность и легальность использования в вашей юрисдикции.
