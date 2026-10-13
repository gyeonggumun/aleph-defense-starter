import { handleDeviceRequest } from '../src/device-approval.mjs';

export default function handler(request, response) {
  return handleDeviceRequest(request, response);
}
