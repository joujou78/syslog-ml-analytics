// FastAPI's `detail` is a plain string for an error we raise ourselves
// (e.g. HTTPException(detail="...")), but a list of structured objects
// for an automatic Pydantic validation error (422) -- rendering that list
// directly as a React child throws, so every catch block that reads
// err.response.data.detail needs to go through this instead.
export function extractErrorMessage(err: unknown, fallback: string): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail
      .map((d) => (d && typeof d === 'object' && 'msg' in d ? String((d as { msg: unknown }).msg) : JSON.stringify(d)))
      .join('; ')
  }
  return fallback
}
