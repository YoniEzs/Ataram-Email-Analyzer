"""Shared parsing helpers for RDAP payloads (domain and IP objects alike)."""

from typing import Any, Dict, List, Optional, Set


def event_date(payload: Dict[str, Any], actions: Set[str]) -> Optional[str]:
    """First ``eventDate`` whose ``eventAction`` is in ``actions``."""
    for event in payload.get('events', []) or []:
        if str(event.get('eventAction', '')).lower() in actions:
            value = event.get('eventDate')
            return str(value) if value else None
    return None


def _vcard_rows(entity: Dict[str, Any]) -> List[Any]:
    vcard = entity.get('vcardArray') or []
    return vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []


def vcard_field(entity: Dict[str, Any], field: str) -> Optional[str]:
    """Value of a vCard row such as ``fn`` or ``email``."""
    for row in _vcard_rows(entity):
        if isinstance(row, list) and len(row) >= 4 and row[0] == field:
            value = row[3]
            if isinstance(value, list):
                value = next((v for v in value if v), None)
            return str(value) if value else None
    return None


def entity_with_role(payload: Dict[str, Any], role: str) -> Optional[Dict[str, Any]]:
    """First entity carrying ``role``, searched one level into sub-entities."""
    for entity in payload.get('entities', []) or []:
        if not isinstance(entity, dict):
            continue
        roles = {str(r).lower() for r in (entity.get('roles') or [])}
        if role in roles:
            return entity
        for sub in entity.get('entities', []) or []:
            if not isinstance(sub, dict):
                continue
            sub_roles = {str(r).lower() for r in (sub.get('roles') or [])}
            if role in sub_roles:
                return sub
    return None


def entity_name(payload: Dict[str, Any], role: str) -> Optional[str]:
    """Display name (``fn``, else handle) of the entity holding ``role``."""
    entity = entity_with_role(payload, role)
    if entity is None:
        return None
    name = vcard_field(entity, 'fn')
    if name:
        return name
    handle = entity.get('handle')
    return str(handle) if handle else None
