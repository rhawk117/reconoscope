


import phonenumbers
from phonenumbers import geocoder
from phonenumbers import carrier

from modules.models import PhoneRecord


def get_phone_info(phone_number: str) -> PhoneRecord:
    try:
        phone_obj = phonenumbers.parse(phone_number)
    except phonenumbers.NumberParseException as exc:
        raise ValueError(f"Error parsing phone number {phone_number}: {exc}")

    if is_valid := phonenumbers.is_valid_number(phone_obj):
        kwargs = {
            "e164": phonenumbers.format_number(
                phone_obj, phonenumbers.PhoneNumberFormat.E164
            ),
            "country": geocoder.country_name_for_number(phone_obj, "en"),
            "region": geocoder.description_for_number(phone_obj, "en"),
            "operator": carrier.name_for_number(phone_obj, "en"),
        }
    else:
        kwargs = {
            "e164": None,
            "country": None,
            "region": None,
            "operator": None,
        }

    return PhoneRecord(
        phone_number=phone_number,
        is_valid=is_valid,
        **kwargs
    )
