import { handleNotesRequest } from '../src/notes-api.mjs';

export default function handler(request, response) {
  return handleNotesRequest(request, response);
}
