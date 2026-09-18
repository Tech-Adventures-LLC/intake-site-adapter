export default async function publicCanary(_request, response) {
  return response.status(200).json({ ok: true, site: 'fixture-site' });
}
