# API Reference

Base URL: `http://localhost:8000/api`. Auth via `session_token` HttpOnly
cookie (set by `/auth/login`). All endpoints below require auth unless
marked otherwise.

## Auth
| Method | Path | Notes |
|---|---|---|
| POST | `/auth/login` | `{username, password}` -> sets cookie |
| POST | `/auth/logout` | clears cookie |
| GET | `/auth/me` | current user + roles |

## Investigations & PCAP
| Method | Path | Notes |
|---|---|---|
| POST | `/investigations` | `?title=` -> creates empty investigation |
| GET | `/investigations` | list, newest first |
| GET | `/investigations/{id}` | detail incl. PCAP metadata, finding count |
| POST | `/pcaps/upload` | multipart `file` + `?title=` -> validates, hashes, queues background analysis |
| GET | `/pcaps/{id}/status` | investigation status for this PCAP |

## Sessions / TLS / Certificates
| Method | Path | Notes |
|---|---|---|
| GET | `/sessions?investigation_id=` | list network sessions |
| GET | `/sessions/{id}` | session + email/STARTTLS detail |
| GET | `/sessions/{id}/tls` | TLS handshake summary |
| GET | `/sessions/{id}/certificate` | certificate chain, per position |
| GET | `/risk/{session_id}` | latest fused risk score |
| GET | `/ai/{session_id}` | latest ML model run + top contributors |

## Findings & Evidence
| Method | Path | Notes |
|---|---|---|
| GET | `/findings?investigation_id=` | list |
| GET | `/findings/{id}` | detail + linked evidence |
| GET | `/evidence/{id}` | single evidence record |

## Reports
| Method | Path | Notes |
|---|---|---|
| POST | `/reports?investigation_id=&format=PDF\|JSON\|HTML` | generates and stores a report |
| GET | `/reports/{id}` | downloads the file |

## Assistant
| Method | Path | Notes |
|---|---|---|
| POST | `/assistant` | `{message, investigation_id?}` -> local KB reply, or a real summary of that investigation's findings |

## System / Demo (no auth)
| Method | Path | Notes |
|---|---|---|
| GET | `/system/dependencies` | tshark/scapy/cryptography/DB/ML runtime availability |
| POST | `/demo/load` | seeds and returns a synthetic `is_demo=true` investigation |
| GET | `/health` | liveness check |

## Audit
| Method | Path | Notes |
|---|---|---|
| GET | `/audit-log` | admin role only, most recent 200 entries |

## Error shape
Unhandled errors return `500` with `{"error": "...", "detail": "..."}`
(never silently swallowed — see `SECURITY.md` / section 43 "never hide
errors"). Validation errors from PCAP upload return `400` with a specific
message (`EMPTY_PCAP`, `INVALID_PCAP: ...`, unsupported extension, etc.).
