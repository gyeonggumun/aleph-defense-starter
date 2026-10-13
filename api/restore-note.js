import { handleRestoreNote } from '../src/restore-note.mjs';

export default function handler(request, response) {
  return handleRestoreNote(request, response);
}
