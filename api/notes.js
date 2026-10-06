import { createClient } from '@supabase/supabase-js';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) return response.status(503).json({ error: 'DATABASE_NOT_CONFIGURED' });

  try {
    const supabase = createClient(url, secretKey, {
      auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
    });
    const { data, error } = await supabase
      .from('vault_notes')
      .select('id,title,content')
      .order('id', { ascending: true });
    if (error) return response.status(502).json({ error: 'DATA_SOURCE_UNAVAILABLE' });
    return response.status(200).json({ sampleMarker: 'SAMPLE_NOTE_1', notes: data ?? [] });
  } catch {
    return response.status(502).json({ error: 'DATA_SOURCE_UNAVAILABLE' });
  }
}
