import { handleOperationsRequest } from '../src/operations-api.mjs';

export default function handler(request, response) {
  return handleOperationsRequest(request, response);
}
