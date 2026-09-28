# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from genlayer.py.public_abi import StorageType
from dataclasses import dataclass
import base64
import hashlib
import re
_WSP = re.compile(rb"[ \t]+")
_DELIMITER = re.compile(rb"(?m)^--(\S+?)[ \t]*\r?$")
_QP_HEX = re.compile(rb"=([0-9A-Fa-f]{2})")
_PART_SEPARATORS = (b"\r\n\r\n", b"\n\n")
_ACCENTS = str.maketrans("\u00e1\u00e9\u00ed\u00f3\u00fa\u00fc\u00f1", "aeiouun")
WEEKDAYS = ("lunes", "martes", "miercoles", "jueves", "viernes", "sabado",
"domingo")
def canonicalize_body_simple(body):
 if body and not body.endswith(b"\r\n"):
  body += b"\r\n"
 while body.endswith(b"\r\n\r\n"):
  body = body[:-2]
 return body or b"\r\n"
def canonicalize_body_relaxed(body):
 lines = [_WSP.sub(b" ", line).rstrip(b" ") for line in body.split(b"\r\n")]
 while lines and not lines[-1]:
  lines.pop()
 if not lines:
  return b""
 return b"\r\n".join(lines) + b"\r\n"
def canonicalize_body(body, canon):
 if canon == "simple":
  return canonicalize_body_simple(body)
 if canon == "relaxed":
  return canonicalize_body_relaxed(body)
 raise ValueError("unsupported body canonicalization")
def body_hash_b64(body, canon):
 digest = hashlib.sha256(canonicalize_body(body, canon)).digest()
 return base64.b64encode(digest).decode("ascii")
def qp_decode(data):
 data = data.replace(b"=\r\n", b"").replace(b"=\n", b"")
 return _QP_HEX.sub(lambda hit: bytes([int(hit.group(1), 16)]), data)
def split_part(part):
 found = [(part.find(sep), sep) for sep in _PART_SEPARATORS]
 found = [(index, sep) for index, sep in found if index >= 0]
 if not found:
  return b"", part
 index, sep = min(found)
 return part[:index].lower(), part[index + len(sep):]
def first_text_part(raw_bytes):
 delimiter = _DELIMITER.search(raw_bytes)
 if not delimiter:
  return b""
 for part in raw_bytes.split(b"--" + delimiter.group(1))[1:]:
  head, payload = split_part(part.lstrip(b"-\r\n"))
  if b"text/plain" not in head:
   continue
  if b"quoted-printable" in head:
   return qp_decode(payload)
  if b"base64" in head:
   payload = re.sub(rb"\s", b"", payload)
   return base64.b64decode(payload + b"=" * (-len(payload) % 4))
  return payload
 return b""
import json
KEYS = ["eta_date", "eta_day", "order_id", "shipped"]
MAX_PATTERNS = 4096
MAX_BODY = 262144
def clean_document(document):
 return str(document).strip()
def document_sha256(document):
 return hashlib.sha256(clean_document(document).encode()).hexdigest()
def load_patterns(document):
 text = clean_document(document)
 if len(text.encode()) > MAX_PATTERNS:
  raise ValueError("patterns too large")
 try:
  doc = json.loads(text)
 except ValueError:
  raise ValueError("patterns not JSON")
 if (not isinstance(doc, dict) or sorted(doc) != KEYS
or not all(isinstance(doc[key], list) for key in KEYS)):
  raise ValueError("patterns need lists under " + " ".join(KEYS))
 for key in KEYS:
  for expr in doc[key]:
   try:
    groups = re.compile(expr).groupindex
   except (re.error, TypeError):
    raise ValueError("patterns key does not compile: " + key)
   if key == "eta_date" and not {"y", "m", "d"} <= set(groups):
    raise ValueError("eta_date needs groups y m d")
 return doc
def weekday(hit):
 word = hit.group(1 if hit.re.groups else 0)
 return word if word in WEEKDAYS else ""
def iso_date(hit):
 y, m, d = (hit.group(key) or "" for key in "ymd")
 if not re.fullmatch("[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}", "-".join((y, m, d))):
  return ""
 y, m, d = int(y), int(m), int(d)
 leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
 last = 28 + leap if m == 2 else 30 + (m + m // 8) % 2
 return "%04d-%02d-%02d" % (y, m, d) if 0 < m < 13 and 0 < d <= last else ""
def first_value(exprs, text, pick):
 for expr in exprs:
  hit = re.search(expr, text)
  if hit and pick(hit):
   return pick(hit)
 return ""
def canonical(reason, digest, match=0, shipped=0, day="", date="", order=0):
 return "%d|%d|%s|%s|%d|%s|%s" % (match, shipped, day, date, order, digest,
reason.replace("|", " ")[:96])
def extract_body(raw, bh, canon, document):
 digest = document_sha256(document)
 if len(raw) > MAX_BODY:
  return canonical("body too large", digest)
 try:
  if body_hash_b64(raw, canon) != bh:
   return canonical("bh mismatch", digest)
  text = first_text_part(raw)
  if not text:
   return canonical("no text part", digest, 1)
  doc = load_patterns(document)
  folded = text.decode("utf-8", "replace").translate(_ACCENTS).lower()
  return canonical(
"extracted", digest, 1,
any(re.search(expr, folded) for expr in doc["shipped"]),
first_value(doc["eta_day"], folded, weekday),
first_value(doc["eta_date"], folded, iso_date),
any(re.search(expr, folded) for expr in doc["order_id"]))
 except Exception as error:
  return canonical("extract failed: " + type(error).__name__, digest)
ZERO_ADDRESS = Address(bytes(20))
FIELDS = ("verifier record_id domain bh match reason patterns_sha256 shipped eta_day eta_date"
" order_id_found signed_at requester extracted_at fee_paid").split()
@gl.evm.contract_interface
class _Recipient:
 class View:
  pass
 class Write:
  pass
def normalize(value):
 return str(value).strip().lower().strip(".")
def as_address(value):
 try:
  return Address(str(value).strip())
 except Exception:
  raise gl.vm.UserError("[EXPECTED] not a 20 byte hex address")
def proposed(value):
 candidate = as_address(value)
 if candidate == ZERO_ADDRESS:
  raise gl.vm.UserError("[EXPECTED] the zero address cannot be proposed")
 return candidate
def claimed(pending, role):
 if pending == ZERO_ADDRESS or gl.message.sender_address != pending:
  raise gl.vm.UserError("[EXPECTED] pending %s only" % (role,))
 return pending
def holder(requester):
 try:
  return as_address(requester).as_hex
 except Exception:
  return ""
def shown(address):
 return "" if address == ZERO_ADDRESS else address.as_hex
def require_owner(owner):
 if gl.message.sender_address != owner:
  raise gl.vm.UserError("[EXPECTED] owner only")
def verified(router, record_id):
 final = StorageType.LATEST_FINAL
 why = "router unreadable"
 try:
  verifier = gl.get_contract_at(router).view(state=final).resolve("verifier")
  if not verifier:
   return "router resolves no verifier", None, {}
  why = "verifier unreadable"
  address = Address(verifier)
  record = dict(gl.get_contract_at(address).view(state=final).get(record_id))
 except Exception:
  return why, None, {}
 return ("record not found" if not record
else "record not valid" if record.get("valid") is not True
else "record not aligned" if record.get("aligned") is not True
else "body canonicalization not supported"
if record.get("body_canon") not in ("simple", "relaxed")
else ""), address, record
def fetched(url, bh, canon, document):
 try:
  response = gl.nondet.web.get(url, headers={"accept": "*/*"})
  status = int(getattr(response, "status", 0) or 0)
  if status == 200:
   return extract_body(response.body or b"", bh, canon, document)
  reason = "body HTTP %d" % (status,)
 except Exception as error:
  reason = "body fetch failed: " + type(error).__name__
 return canonical(reason, document_sha256(document))
@allow_storage
@dataclass
class Extraction:
 verifier: Address
 record_id: str
 domain: str
 bh: str
 match: bool
 reason: str
 patterns_sha256: str
 shipped: bool
 eta_day: str
 eta_date: str
 order_id_found: bool
 signed_at: u256
 requester: Address
 extracted_at: str
 fee_paid: u256
class Contract(gl.Contract):
 owner_address: Address
 pending_owner_address: Address
 router_address: Address
 treasury_address: Address
 pending_treasury_address: Address
 fee_wei: u256
 records: TreeMap[str, Extraction]
 record_count: u256
 documents: TreeMap[str, str]
 ids_of: TreeMap[str, DynArray[str]]
 refusals: TreeMap[str, str]
 def __init__(self, router: str):
  self.owner_address = gl.message.sender_address
  self.treasury_address = gl.message.sender_address
  self.router_address = as_address(router)
 def _refuse(self, reason):
  who = gl.message.sender_address
  self.refusals[who.as_hex] = reason
  if gl.message.value:
   _Recipient(who).emit_transfer(value=gl.message.value)
  return reason
 @gl.public.write.payable
 def extract(self, record_id: str, body_url: str) -> str:
  if gl.message.value < self.fee_wei:
   return self._refuse("fee not paid")
  source = str(record_id).strip()
  why, verifier, record = verified(self.router_address, source)
  if why:
   return self._refuse(why)
  domain = str(record.get("domain"))
  document = self.documents.get(domain)
  if document is None:
   return self._refuse("no patterns for domain")
  url = str(body_url).strip()
  if not url.startswith("https://") or len(url) > 512:
   return self._refuse("url not allowed")
  bh = str(record.get("bh"))
  canon = str(record.get("body_canon"))
  def probe() -> str:
   return fetched(url, bh, canon, document)
  parts = (str(gl.eq_principle.strict_eq(probe)).split("|") + [""] * 7)[:7]
  match = parts[0] == "1"
  signed = str(record.get("signed_at"))
  new_id = str(self.record_count)
  self.records[new_id] = Extraction(
verifier=verifier, record_id=source, domain=domain, bh=bh,
match=match, reason=parts[6][:96], patterns_sha256=document_sha256(document),
shipped=match and parts[1] == "1",
eta_day=parts[2] if match and parts[2] in WEEKDAYS else "",
eta_date=parts[3] if match and re.fullmatch("[0-9]{4}-[0-9]{2}-[0-9]{2}", parts[3]) else "",
order_id_found=match and parts[4] == "1",
signed_at=u256(int(signed) if signed.isascii() and signed.isdigit() else 0),
requester=gl.message.sender_address,
extracted_at=str(gl.message_raw["datetime"]),
fee_paid=u256(gl.message.value),
)
  self.record_count += 1
  self.ids_of.get_or_insert_default(gl.message.sender_address.as_hex).append(new_id)
  return new_id
 @gl.public.write
 def set_patterns(self, domain: str, patterns_json: str) -> str:
  require_owner(self.owner_address)
  name = normalize(domain)
  if not name:
   raise gl.vm.UserError("[EXPECTED] bad domain")
  try:
   load_patterns(patterns_json)
  except ValueError as error:
   raise gl.vm.UserError("[EXPECTED] " + str(error))
  self.documents[name] = clean_document(patterns_json)
  return document_sha256(patterns_json)
 @gl.public.view
 def patterns(self, domain: str) -> str:
  return self.documents.get(normalize(domain), "")
 @gl.public.view
 def patterns_sha256(self, domain: str) -> str:
  document = self.patterns(domain)
  return document_sha256(document) if document else ""
 @gl.public.view
 def get_record(self, id: str) -> dict:
  held = self.records.get(str(id))
  if held is None:
   return {}
  out = {"id": str(id), "schema_version": "1", "method": "patterns"}
  for key in FIELDS:
   value = getattr(held, key)
   out[key] = (value.as_hex if isinstance(value, Address)
else value if isinstance(value, (bool, str)) else str(value))
  return out
 @gl.public.view
 def records_of(self, requester: str) -> list:
  return list(self.ids_of.get(holder(requester), []))
 @gl.public.view
 def last_refusal(self, requester: str) -> str:
  return self.refusals.get(holder(requester), "")
 @gl.public.view
 def count(self) -> int:
  return int(self.record_count)
 @gl.public.view
 def fee(self) -> int:
  return int(self.fee_wei)
 @gl.public.view
 def treasury(self) -> str:
  return self.treasury_address.as_hex
 @gl.public.view
 def router(self) -> str:
  return self.router_address.as_hex
 @gl.public.view
 def owner(self) -> str:
  return self.owner_address.as_hex
 @gl.public.view
 def pending_owner(self) -> str:
  return shown(self.pending_owner_address)
 @gl.public.view
 def pending_treasury(self) -> str:
  return shown(self.pending_treasury_address)
 @gl.public.write
 def set_fee(self, new_fee: int) -> str:
  require_owner(self.owner_address)
  if new_fee < 0:
   raise gl.vm.UserError("[EXPECTED] negative fee")
  self.fee_wei = u256(new_fee)
  return str(new_fee)
 @gl.public.write
 def propose_owner(self, address: str) -> str:
  require_owner(self.owner_address)
  self.pending_owner_address = proposed(address)
  return self.pending_owner_address.as_hex
 @gl.public.write
 def accept_owner(self) -> str:
  self.owner_address = claimed(self.pending_owner_address, "owner")
  self.pending_owner_address = ZERO_ADDRESS
  return self.owner_address.as_hex
 @gl.public.write
 def propose_treasury(self, address: str) -> str:
  require_owner(self.owner_address)
  self.pending_treasury_address = proposed(address)
  return self.pending_treasury_address.as_hex
 @gl.public.write
 def accept_treasury(self) -> str:
  self.treasury_address = claimed(self.pending_treasury_address, "treasury")
  self.pending_treasury_address = ZERO_ADDRESS
  return self.treasury_address.as_hex
 @gl.public.write
 def withdraw(self, amount: int) -> str:
  require_owner(self.owner_address)
  if amount <= 0 or amount > self.balance:
   raise gl.vm.UserError("[EXPECTED] amount out of range")
  _Recipient(self.treasury_address).emit_transfer(value=u256(amount))
  return str(amount)
