// Bounded intake-contract-v1 fields. Golden tests validate emitted commands against P01.
export const FIELD_LIMITS = Object.freeze({
  "contact": {
    "name": 160,
    "email": 320,
    "phone": 40
  },
  "details": {
    "company": 160,
    "location": 160,
    "project_type": 80,
    "timeline": 80,
    "show_name": 160,
    "booth_size": 80,
    "postal_code": 16,
    "vehicle_year": 4,
    "vehicle_make_model": 160,
    "vehicle_type": 80,
    "tint_coverage": 160,
    "windshield": 80,
    "tint_removal": 80,
    "service_location": 160,
    "preferred_shade": 80,
    "estimated_duration": 80,
    "notes": 1200,
    "message": 3000
  },
  "attribution": {
    "source": 160,
    "medium": 160,
    "campaign": 160,
    "term": 160,
    "content": 160,
    "page": 500,
    "landing_page": 240,
    "referrer": 500,
    "utm_source": 160,
    "utm_medium": 160,
    "utm_campaign": 160,
    "utm_term": 160,
    "utm_content": 160,
    "first_touch_at": 40,
    "last_source": 160,
    "last_medium": 160,
    "last_campaign": 160,
    "last_term": 160,
    "last_content": 160,
    "last_landing_page": 240,
    "last_referrer": 500,
    "last_touch_at": 40,
    "click_id_type": 24,
    "click_id": 240,
    "ga_client_id": 80,
    "ga_session_id": 80,
    "tracking_id": 80,
    "navigation_path": 5000
  },
  "consent": {
    "contact_request": null,
    "phone_contact": null,
    "sms": null,
    "disclosure_version": 64
  }
});

export function validCommand(command) {
  for (const [section, fields] of Object.entries(FIELD_LIMITS)) {
    for (const [key, value] of Object.entries(command[section] ?? {})) {
      const limit = fields[key];
      if (limit === undefined) return false;
      if (section === 'consent' && key !== 'disclosure_version') {
        if (typeof value !== 'boolean') return false;
      } else if (!(section === 'contact' && key === 'phone' && value === null)) {
        if (typeof value !== 'string' || [...value].length > limit) return false;
      }
    }
  }
  const contact = command.contact;
  if (!contact || typeof contact.name !== 'string' || !contact.name.trim() || typeof contact.email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact.email)) return false;
  const consent = command.consent ?? {};
  const phoneConsent = consent.phone_contact === true || consent.sms === true;
  if (consent.sms === true && consent.phone_contact !== true) return false;
  if (phoneConsent && (typeof contact.phone !== 'string' || !contact.phone.trim() || typeof consent.disclosure_version !== 'string' || !consent.disclosure_version.trim())) return false;
  if (typeof consent.disclosure_version === 'string' && consent.disclosure_version.trim() && !phoneConsent) return false;
  return true;
}
