from __future__ import annotations

import re
from dataclasses import dataclass

from .models import (
    EventRecord,
    FindingCategory,
    FindingSeed,
)


@dataclass(frozen=True)
class RuleDefinition:
    event_id: int
    category: FindingCategory
    priority: int
    title: str
    explanation: str
    recommendation: str
    channel: str | None = None
    provider_contains: str | None = None
    key_fields: tuple[str, ...] = ()
    suppress_finding: bool = False


RULES = (
    RuleDefinition(
        104,
        FindingCategory.CRITICAL,
        100,
        "Журнал событий был очищен",
        "Очистка системного журнала удаляет важные сведения для расследования.",
        "Проверить инициатора очистки, соседние события и регламент обслуживания.",
        channel="System",
        provider_contains="Eventlog",
    ),
    RuleDefinition(
        1102,
        FindingCategory.CRITICAL,
        100,
        "Журнал аудита безопасности был очищен",
        "Очистка журнала Security может скрывать действия пользователя или нарушителя.",
        "Установить учётную запись инициатора и проверить централизованные копии журнала.",
        channel="Security",
        key_fields=("SubjectUserName", "SubjectDomainName"),
    ),
    RuleDefinition(
        4719,
        FindingCategory.CRITICAL,
        95,
        "Изменена политика аудита безопасности",
        "Изменение политики может уменьшить объём регистрируемых событий.",
        "Сопоставить изменение с утверждённой заявкой и проверить новые параметры аудита.",
        channel="Security",
        key_fields=("SubjectUserName", "CategoryId", "SubcategoryGuid"),
    ),
    RuleDefinition(
        4720,
        FindingCategory.SECURITY,
        75,
        "Создана учётная запись пользователя",
        "Новая учётная запись требует подтверждения её назначения и владельца.",
        "Проверить инициатора, членство в группах и соответствие заявке.",
        channel="Security",
        key_fields=("TargetDomainName", "TargetUserName", "SubjectUserName"),
    ),
    RuleDefinition(
        4726,
        FindingCategory.SECURITY,
        65,
        "Удалена учётная запись пользователя",
        "Удаление учётной записи влияет на доступ и аудит действий.",
        "Проверить инициатора удаления и наличие согласованной заявки.",
        channel="Security",
        key_fields=("TargetDomainName", "TargetUserName", "SubjectUserName"),
    ),
    RuleDefinition(
        4728,
        FindingCategory.SECURITY,
        85,
        "Участник добавлен в глобальную группу безопасности",
        "Добавление в группу может предоставить дополнительные привилегии.",
        "Проверить добавленного участника, группу, инициатора и основание изменения.",
        channel="Security",
        key_fields=("TargetUserName", "MemberName", "MemberSid", "SubjectUserName"),
    ),
    RuleDefinition(
        4732,
        FindingCategory.SECURITY,
        85,
        "Участник добавлен в локальную группу безопасности",
        "Добавление в локальную группу может предоставить административные права.",
        "Проверить группу, участника и инициатора изменения.",
        channel="Security",
        key_fields=("TargetUserName", "MemberName", "MemberSid", "SubjectUserName"),
    ),
    RuleDefinition(
        4756,
        FindingCategory.SECURITY,
        85,
        "Участник добавлен в универсальную группу безопасности",
        "Изменение универсальной группы может расширить права в домене.",
        "Проверить группу, участника и согласованность изменения.",
        channel="Security",
        key_fields=("TargetUserName", "MemberName", "MemberSid", "SubjectUserName"),
    ),
    RuleDefinition(
        4738,
        FindingCategory.SECURITY,
        65,
        "Изменена учётная запись пользователя",
        "Изменение атрибутов учётной записи может повлиять на доступ.",
        "Проверить изменённые поля, инициатора и основание изменения.",
        channel="Security",
        key_fields=("TargetDomainName", "TargetUserName", "SubjectUserName"),
    ),
    RuleDefinition(
        4740,
        FindingCategory.SECURITY,
        70,
        "Учётная запись заблокирована",
        "Блокировка может указывать на ошибочный пароль, сбой службы или подбор.",
        "Проверить CallerComputerName, источники входа и сохранённые учётные данные.",
        channel="Security",
        key_fields=("TargetDomainName", "TargetUserName", "CallerComputerName"),
    ),
    RuleDefinition(
        4771,
        FindingCategory.SECURITY,
        60,
        "Ошибка предварительной проверки Kerberos",
        "Повторяющиеся ошибки могут указывать на неверные пароли или подбор.",
        "Проверить адрес клиента, код ошибки и связанную учётную запись.",
        channel="Security",
        key_fields=("TargetUserName", "IpAddress", "Status"),
    ),
    RuleDefinition(
        7045,
        FindingCategory.SECURITY,
        75,
        "Установлена новая системная служба",
        "Новая служба запускает код с системными или пользовательскими правами.",
        "Проверить путь, подпись файла, тип запуска и основание установки.",
        channel="System",
        key_fields=("ServiceName", "ImagePath", "AccountName"),
    ),
    RuleDefinition(
        1116,
        FindingCategory.SECURITY,
        90,
        "Microsoft Defender обнаружил угрозу",
        "Защитное средство зарегистрировало вредоносный или нежелательный объект.",
        "Проверить Threat Name, путь, пользователя и последующее событие устранения.",
        provider_contains="Defender",
        key_fields=("Threat ID", "Threat Name", "Path"),
    ),
    RuleDefinition(
        1117,
        FindingCategory.SECURITY,
        0,
        "Microsoft Defender выполнил действие",
        "Событие используется для корреляции результата устранения угрозы.",
        "Проверить результат действия и состояние объекта.",
        provider_contains="Defender",
        key_fields=("Threat ID", "Threat Name", "Path"),
        suppress_finding=True,
    ),
    RuleDefinition(
        5001,
        FindingCategory.CRITICAL,
        98,
        "Защита Microsoft Defender в реальном времени отключена",
        "Отключение защиты увеличивает риск незамеченного запуска вредоносного ПО.",
        "Установить инициатора, восстановить защиту и проверить соседние события.",
        provider_contains="Defender",
    ),
    RuleDefinition(
        5007,
        FindingCategory.SECURITY,
        70,
        "Изменена конфигурация Microsoft Defender",
        "Изменение параметров защиты требует подтверждения.",
        "Проверить изменённый параметр, инициатора и соответствие политике.",
        provider_contains="Defender",
        key_fields=("New Value", "Old Value"),
    ),
)

CANDIDATE_EVENT_IDS = {rule.event_id for rule in RULES} | {4625}


def lookup_specific_rule(event: EventRecord) -> RuleDefinition | None:
    for rule in RULES:
        if rule.event_id != event.event_id:
            continue
        if rule.channel and rule.channel.casefold() != event.channel.casefold():
            continue
        if (
            rule.provider_contains
            and rule.provider_contains.casefold() not in event.provider.casefold()
        ):
            continue
        return rule
    return None


def _clean(value: str) -> str:
    return " ".join(value.strip().split()) or "—"


def _message_signature(event: EventRecord) -> str:
    message = event.rendered_message or ""
    if not message:
        fields = [
            f"{key}={_clean(value)}"
            for key, value in sorted(event.data.items())[:8]
        ]
        message = "|".join(fields)
    message = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "{guid}", message, flags=re.I)
    message = re.sub(r"\b0x[0-9a-f]+\b", "{hex}", message, flags=re.I)
    message = re.sub(r"\b\d{4,}\b", "{number}", message)
    return _clean(message).casefold()


def seed_from_rule(
    event: EventRecord, rule: RuleDefinition
) -> FindingSeed:
    fields = tuple(_clean(event.data.get(name, "")) for name in rule.key_fields)
    return FindingSeed(
        category=rule.category,
        priority=rule.priority,
        title=rule.title,
        explanation=rule.explanation,
        recommendation=rule.recommendation,
        grouping_key=(
            event.node,
            event.channel,
            event.provider,
            str(event.event_id),
            rule.title,
            *fields,
        ),
        event=event,
    )


def generic_seed(
    event: EventRecord,
    category: FindingCategory,
    priority: int,
) -> FindingSeed:
    source = event.provider or "Неизвестный поставщик"
    label = "Критическое событие" if category is FindingCategory.CRITICAL else "Ошибка"
    explanation = event.rendered_message or (
        "Описание поставщика недоступно; показаны технические поля события."
    )
    return FindingSeed(
        category=category,
        priority=priority,
        title=f"{label}: {source} (Event ID {event.event_id})",
        explanation=explanation,
        recommendation=(
            "Проверить технические поля, соседние события и состояние связанного компонента."
        ),
        grouping_key=(
            event.node,
            event.channel,
            source,
            str(event.event_id),
            _message_signature(event),
        ),
        event=event,
    )


def classify_event(event: EventRecord) -> list[FindingSeed]:
    if event.event_id == 4625:
        return []
    rule = lookup_specific_rule(event)
    if rule is not None:
        return [] if rule.suppress_finding else [seed_from_rule(event, rule)]
    if event.level == 1:
        return [generic_seed(event, FindingCategory.CRITICAL, 90)]
    if event.level == 2:
        return [generic_seed(event, FindingCategory.ERROR, 50)]
    return []


def is_candidate_event(event: EventRecord) -> bool:
    return is_candidate_metadata(event.event_id, event.level)


def is_candidate_metadata(event_id: int, level: int | None) -> bool:
    return level in {1, 2} or event_id in CANDIDATE_EVENT_IDS
