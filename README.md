# Rulesets

Автоматически обновляемые доменные и IP-списки для Xray/V2Ray, Mihomo и sing-box, а также список Android-пакетов для INCY. Исходники нормализуются один раз; отдельные сборщики выпускают нужные форматы из ветки `sources`.

## Где что находится

| Ветка | Содержимое | Назначение |
|---|---|---|
| `main` | `.github/workflows/`, `.ci/`, `data/`, `apps.txt` | Сборка, точка расширения локальными списками и список приложений |
| `sources` | `geosite/*.list`, `geoip/*.list` | Развёрнутые текстовые категории без `include:` |
| `xray-rulesets` | `geosite.dat`, `geoip.dat`, `*.hash` | Выбранные клиентские категории для Xray/V2Ray |
| `server` | `geosite.dat`, `geoip.dat`, `*.hash` | Отдельный серверный набор блокировок |
| `mihomo-rulesets` | `geosite-*.mrs`, `geoip-*.mrs`, `mrs.hash`, `mrs.manifest.json` | Все поддерживаемые категории в формате Mihomo |
| `sing-box-rulesets` | `geosite-*.srs`, `geoip-*.srs`, `srs.hash`, `srs.manifest.json` | Все категории в формате sing-box |

Ветки с результатами отделены от кода, чтобы клиенты скачивали только данные. В каждой из пяти выходных веток сохраняется не больше трёх последних снимков; публикация защищена `--force-with-lease` от перезаписи чужого обновления.

### Код

- [`.github/workflows/sources.yml`](.github/workflows/sources.yml) — загрузка исходников, разворачивание включений, нормализация и публикация текстовых списков.
- [`.github/workflows/xray.yml`](.github/workflows/xray.yml), [`server.yml`](.github/workflows/server.yml) — сборка выбранных категорий в DAT.
- [`.github/workflows/mihomo.yml`](.github/workflows/mihomo.yml), [`sing-box.yml`](.github/workflows/sing-box.yml) — инкрементальная сборка MRS/SRS.
- [`.github/workflows/apps.yml`](.github/workflows/apps.yml) — независимое обновление `apps.txt`.
- [`.ci/optimize.py`](.ci/optimize.py) — нормализация доменов, рекурсивные `include:` с атрибутами, удаление доказуемых перекрытий и агрегация CIDR.
- [`.ci/build_srs.py`](.ci/build_srs.py) — преобразование текстовой категории в исходный JSON sing-box.
- [`.ci/build_apps.py`](.ci/build_apps.py) — извлечение Android-пакетов, сортировка и удаление повторов без изменения регистра.
- [`.ci/publish.py`](.ci/publish.py) — атомарная публикация дерева и ограничение истории выходных веток.
- [`data/`](data/README.md) — точка расширения локальными доменными и IP-списками. Сейчас локальных переопределений нет.

## Откуда берутся списки

Полные URL и выходные имена перечислены в `sources.yml`.

| Источник | Что используется |
|---|---|
| [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) | Все доменные категории с рекурсивным разворачиванием включений |
| [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip), ветка `release` | Текстовые GeoIP-категории |
| [Re-filter-lists](https://github.com/1andrevich/Re-filter-lists) | Доменные и IP-списки `refilter`, `refilter-community` |
| [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) | `russia-inside`, `google-ai`, категории и сервисы `allow-*` |
| [Davoyan/xray-routing](https://github.com/Davoyan/xray-routing) | `davoyan-banned`, `davoyan-category-ru`, `davoyan-ru` |
| [vahellame/russia-whitelist-geosite](https://github.com/vahellame/russia-whitelist-geosite) | `wl`: содержимое `whitelist` вместе с включёнными категориями |
| [vahellame/russia-whitelist-geoip](https://github.com/vahellame/russia-whitelist-geoip) | IPv4 `wl`: объединение `vk`, `yandex`, `other` |
| [OISD](https://github.com/sjhgvr/oisd), [HaGeZi TIF](https://github.com/hagezi/dns-blocklists) | `oisd-big`, `oisd-small`, `tif-full`; их объединение `abuse-full` = OISD Big + TIF Full |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | IPv4-категория `geoip/abuse.list` |
| [v2fly/geoip](https://github.com/v2fly/geoip), ветка `release` | `geoip/private.list` с IPv4 и IPv6 |
| [legiz-ru/mihomo-rule-sets](https://github.com/legiz-ru/mihomo-rule-sets) | Android-пакеты RU-приложений и торрент-клиентов для `apps.txt` |

Локальные файлы `data/geosite/` и `data/geoip/` применяются после внешних источников: **совпавшее имя заменяет категорию, а не дополняет её**. Сейчас собственных списков нет; `nexusmods` полностью берётся из v2fly. Категории с одинаковым содержимым, но разными upstream-именами сохраняются для совместимости.

### Состав DAT

| Набор | `geosite.dat` | `geoip.dat` |
|---|---|---|
| Клиентский `xray-rulesets` | `wl`, `category-ru`, `banned`, `private`, `youtube` | `wl`, `ru`, `private` |
| Серверный `server` | `oisd-big`, `tif-full` | `abuse` |

Клиентские `category-ru`, `banned`, `ru` берутся из соответствующих `davoyan-*` списков, а `youtube` — из категории v2fly. Объединённый `abuse-full` остаётся текстовой категорией и доступен конвертерам, но в серверный DAT не включается: OISD и TIF там разделены.

## Почему преобразования разделены

- В `sources` сохраняются типы `domain:`, `full:`, `keyword:`, `regexp:`. Повторы и доменные перекрытия внутри категории сокращаются; одинаковые категории с разными именами автоматически не удаляются — имена могут использовать внешние клиенты.
- Сведение перекрытий между разными типами правил применяется отдельно при сборке Xray DAT. Иначе правило `keyword:` могло бы удалить домен, который нужен конвертеру Mihomo.
- MRS `domain` не представляет `keyword:` и `regexp:`: такие правила пропускаются, а для категории без поддерживаемых правил файл MRS не создаётся. Для полноты таких правил используйте Xray или SRS.
- SRS сохраняет доменные суффиксы, точные домены, ключевые слова и регулярные выражения. Исходный JSON использует версию формата `3`.
- IPv6 сохраняется в GeoIP `private`; из остальных IP-категорий удаляется намеренно.
- DAT пересобирается только при изменении выбранных входов, сборщика или workflow. MRS/SRS компилируют только изменившиеся категории; обновление компилятора вызывает полную пересборку.
- Повреждённый или отсутствующий обязательный вход останавливает публикацию вместо выпуска неполного набора. Обработчики `workflow_run` запускаются и после неуспешной сборки `sources`, используя последний доступный снимок.

## Обновление

`Generate sources (flattened xray + cidr)` запускается ежедневно в **00:00 UTC**, вручную и при изменении workflow, `.ci/` или `data/` в `main`. После завершения запускаются четыре сборщика форматов.

`Update INCY Android apps` работает отдельно, ежедневно в **00:15 UTC**, вручную и при изменении своих входных скриптов. Обновляет только `apps.txt` обычным коммитом в `main`; в список попадают уникальные Android-пакеты, а не Windows-процессы.

В workflow используются Mihomo `1.19.33`, sing-box **`1.13.21`**, Go `1.27.3` и Ubuntu `26.04`. Actions checkout и setup-go следуют плавающей major-метке **`@v7`** и получают обновления внутри неё автоматически. sing-box намеренно остаётся на ветке `1.13`, без перехода на `1.14`. Архивы Mihomo и sing-box проверяются по SHA-256; сборщики v2fly закреплены полными SHA коммитов релизов. Данные upstream остаются обновляемыми.

## Скачивание

Примеры для этого репозитория:

```text
# Клиентские DAT
https://raw.githubusercontent.com/sweep7125/rulesets/xray-rulesets/geosite.dat
https://raw.githubusercontent.com/sweep7125/rulesets/xray-rulesets/geoip.dat

# Отдельная категория
https://raw.githubusercontent.com/sweep7125/rulesets/sources/geosite/wl.list
https://cdn.jsdelivr.net/gh/sweep7125/rulesets@mihomo-rulesets/geosite-wl.mrs
https://cdn.jsdelivr.net/gh/sweep7125/rulesets@sing-box-rulesets/geosite-wl.srs

# Список Android-пакетов INCY
https://cdn.jsdelivr.net/gh/sweep7125/rulesets@main/apps.txt

# Серверные DAT
https://raw.githubusercontent.com/sweep7125/rulesets/server/geosite.dat
https://raw.githubusercontent.com/sweep7125/rulesets/server/geoip.dat
```

Большой серверный `geosite.dat` превышает лимит jsDelivr **20 MB**: для него используйте GitHub Raw. После изменения файлов Xray/SRS/server/apps workflow запрашивают очистку соответствующего CDN-кеша; у Mihomo отдельного шага purge сейчас нет.

## Локальные инструменты

Рекомендуется Python **3.14**, как в Ubuntu runner. Скрипт оптимизации использует внутренний `re._parser`; системный Python 3.9 не подходит. Внешних Python-зависимостей нет.

```sh
# Преобразовать простой список доменов в Xray-текст
python3 .ci/optimize.py domains input.txt output.list --input-type clean --target suffix

# Подготовить категорию к компиляции sing-box
python3 .ci/build_srs.py geosite output.list rules.json
sing-box rule-set compile --output rules.srs rules.json
```

Полную сетевую сборку и публикацию выполняют GitHub Actions. Тесты, локальные конфигурации и рабочие заметки в репозитории не публикуются.
