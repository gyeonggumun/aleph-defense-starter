import { handleNoticesRequest } from '../src/notices-api.mjs';

export default function handler(request, response) {
  return handleNoticesRequest(request, response);
}
