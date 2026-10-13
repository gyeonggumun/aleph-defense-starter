import { handleStage12ChecksRequest } from '../src/stage12-checks.mjs';

export default function handler(request, response) {
  return handleStage12ChecksRequest(request, response);
}
